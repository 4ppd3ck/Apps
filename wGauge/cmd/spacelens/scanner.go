package main

// Scanner — concurrent disk-usage walk. Each top-level child of the scan
// root gets its own worker goroutine walking its subtree with WalkDir;
// progress counters and the biggest-files top-K are shared under locks.
// Symlinks are never followed (loops and double-counting), unreadable
// entries are tolerated and counted as errors.
//
// The tree is pruned for transport: every directory keeps its maxChildren
// largest entries and aggregates the remainder into one residual pseudo
// node — exact directory totals are preserved because the residual carries
// the summed size of everything it hides.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxChildren = 60 // kept per directory; the rest is aggregated
const topK = 250       // biggest-files list length

// Node is one entry of the transport tree.
type Node struct {
	Path     string  `json:"path"`
	Name     string  `json:"name"`
	Size     int64   `json:"size"`  // bytes, self + descendants
	Files    int64   `json:"files"` // plain-file count, self + descendants
	Dirs     int64   `json:"dirs"`  // directory count, self + descendants
	Errs     int64   `json:"errs"`  // unreadable entries under this node
	IsDir    bool    `json:"isDir"`
	Residual bool    `json:"residual,omitempty"` // aggregated "… N more" node
	Children []*Node `json:"children,omitempty"`
}

// Biggest is one entry of the largest-files ranking.
type Biggest struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// Progress is the live counter set, read via /api/scan/poll while running.
type Progress struct {
	Running   bool      `json:"running"`
	Root      string    `json:"root,omitempty"`
	Roots     []string  `json:"roots,omitempty"`
	Files     int64     `json:"files"`
	Dirs      int64     `json:"dirs"`
	Bytes     int64     `json:"bytes"`
	Errs      int64     `json:"errs"`
	Current   string    `json:"current,omitempty"`
	Started   float64   `json:"started"`
	ElapsedS  float64   `json:"elapsedS"`
	Done      bool      `json:"done"`
	Error     string    `json:"error,omitempty"`
	Tree      *Node     `json:"tree,omitempty"`
	Biggest   []Biggest `json:"biggest,omitempty"`
	DurationS float64   `json:"durationS,omitempty"`
}

// Scanner holds one scan job (a Scanner instance is a job, not a singleton:
// the server keeps the latest one).
type Scanner struct {
	mu       sync.Mutex
	running  bool
	cancel   atomic.Bool
	root     string
	roots    []string
	started  time.Time
	duration time.Duration

	files, dirs, bytes, errs atomic.Int64
	current                  atomic.Value // string

	muBig   sync.Mutex
	biggest []Biggest // kept sorted desc, cap topK

	tree *Node
}

func NewScanner() *Scanner { return &Scanner{} }

// noteBig inserts into the bounded biggest list (mutex-protected).
func (s *Scanner) noteBig(path string, size int64) {
	if size < 1<<20 { // ignore files under 1 MiB — list stays meaningful
		return
	}
	s.muBig.Lock()
	defer s.muBig.Unlock()
	i := sort.Search(len(s.biggest), func(i int) bool { return s.biggest[i].Size < size })
	if len(s.biggest) < topK {
		s.biggest = append(s.biggest, Biggest{})
	}
	if i >= len(s.biggest) {
		return
	}
	copy(s.biggest[i+1:], s.biggest[i:])
	s.biggest[i] = Biggest{Path: path, Size: size}
}

func (s *Scanner) Snapshot() Progress {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := Progress{
		Running: s.running, Root: s.root,
		Files: s.files.Load(), Dirs: s.dirs.Load(), Bytes: s.bytes.Load(),
		Errs: s.errs.Load(), Started: float64(s.started.UnixMilli()) / 1e3,
	}
	if len(s.roots) > 1 {
		p.Roots = append([]string(nil), s.roots...)
	}
	if c, ok := s.current.Load().(string); ok {
		p.Current = c
	}
	if !s.started.IsZero() {
		if s.running {
			p.ElapsedS = time.Since(s.started).Seconds()
		} else {
			p.ElapsedS = s.duration.Seconds()
			p.DurationS = s.duration.Seconds()
			p.Done = true
			p.Tree = s.tree
			s.muBig.Lock()
			p.Biggest = append([]Biggest(nil), s.biggest...)
			s.muBig.Unlock()
		}
	}
	return p
}

func (s *Scanner) Cancel() { s.cancel.Store(true) }

// walkDir walks one subtree serially, returning the subtree node. Parent
// directories are assembled bottom-up from the returned children.
func (s *Scanner) walkDir(dir string, depth int) *Node {
	if s.cancel.Load() {
		return nil
	}
	node := &Node{Path: dir, Name: filepath.Base(dir), IsDir: true}
	if dir == s.root {
		node.Name = dir
	}
	s.dirs.Add(1)
	s.current.Store(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		s.errs.Add(1)
		node.Errs++
		return node
	}
	for _, e := range entries {
		if s.cancel.Load() {
			return node
		}
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			s.errs.Add(1)
			node.Errs++
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// never follow symlinks: loops and double-counted volumes
			s.files.Add(1)
			s.bytes.Add(info.Size())
			node.Size += info.Size()
			node.Files++
			continue
		}
			if info.IsDir() {
				// tolerate unreadable subtrees, skip pseudo-filesystems
				if skipDir(p) {
					continue
				}
				child := s.walkDir(p, depth+1)
				if child == nil {
					return node // canceled mid-walk
				}
				node.Size += child.Size
			node.Files += child.Files
			node.Dirs += child.Dirs + 1
			node.Errs += child.Errs
			node.Children = append(node.Children, child)
			continue
		}
		sz := info.Size()
		s.files.Add(1)
		s.bytes.Add(sz)
		node.Size += sz
		node.Files++
		if info.Mode()&os.ModeSymlink == 0 {
			s.noteBig(p, sz)
		}
		node.Children = append(node.Children, &Node{Path: p, Name: e.Name(), Size: sz, Files: 1})
	}
	return node
}

// skipDir reports pseudo-filesystems and transient OS machinery that would
// produce garbage numbers or hang the walk.
func skipDir(path string) bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return false
	}
	switch path {
	case "/proc", "/sys", "/dev", "/run", "/afs":
		return true // linux pseudo-filesystems; harmless on darwin
	case "/System/Volumes/Data/.Spotlight-V100", "/private/var/vm", "/Volumes":
		return runtime.GOOS == "darwin"
	}
	return false
}

// Start launches the scan in the background; progress via Snapshot().
// Multiple roots are allowed (e.g. several drives or folders at once):
// each is validated, deduped, and the transported tree gets a virtual
// aggregate root with Path "" — the UI must never reveal/delete it.
func (s *Scanner) Start(roots []string) error {
	cleaned := make([]string, 0, len(roots))
	seen := map[string]bool{}
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		abs, err := filepath.Abs(r)
		if err != nil {
			return err
		}
		if seen[abs] {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", abs)
		}
		seen[abs] = true
		cleaned = append(cleaned, abs)
	}
	if len(cleaned) == 0 {
		return fmt.Errorf("no directory to scan")
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	s.running = true
	s.root = cleaned[0]
	s.roots = cleaned
	s.started = time.Now()
	s.duration = 0
	s.tree = nil
	s.mu.Unlock()

	s.cancel.Store(false)
	s.files.Store(0)
	s.dirs.Store(0)
	s.bytes.Store(0)
	s.errs.Store(0)
	s.current.Store("")
	s.muBig.Lock()
	s.biggest = nil
	s.muBig.Unlock()

	go func() {
		var tree *Node
		if len(cleaned) == 1 {
			tree = s.scan(cleaned[0])
		} else {
			tree = s.scanMulti(cleaned)
		}
		s.mu.Lock()
		s.tree = tree
		s.duration = time.Since(s.started)
		s.running = false
		s.mu.Unlock()
	}()
	return nil
}

// scanMulti scans each root and wraps the per-root trees in one virtual
// aggregate node so the rest of the app (UI included) sees a single tree.
func (s *Scanner) scanMulti(roots []string) *Node {
	root := &Node{Name: fmt.Sprintf("%d locations", len(roots)), IsDir: true}
	for _, r := range roots {
		if s.cancel.Load() {
			break
		}
		sub := s.scan(r)
		root.Size += sub.Size
		root.Files += sub.Files
		root.Dirs += sub.Dirs + 1
		root.Errs += sub.Errs
		root.Children = append(root.Children, sub)
	}
	return root
}

// scan runs the concurrent pass: the root's direct entries are split among
// workers, each subtree walked serially; the root node is assembled after.
func (s *Scanner) scan(root string) *Node {
	entries, err := os.ReadDir(root)
	if err != nil {
		s.errs.Add(1)
	}
	rootNode := &Node{Path: root, Name: root, IsDir: true}
	type result struct {
		idx  int
		node *Node
	}
	var wg sync.WaitGroup
	results := make([]result, 0, len(entries))
	ch := make(chan result, len(entries)+8)
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	idx := 0
	next := func() (int, os.DirEntry, bool) {
		if idx >= len(entries) {
			return 0, nil, false
		}
		i := idx
		idx++
		return i, entries[i], true
	}
	var mu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				i, e, ok := next()
				mu.Unlock()
				if !ok {
					return
				}
				if s.cancel.Load() {
					return
				}
				info, err := e.Info()
				if err != nil {
					s.errs.Add(1)
					continue
				}
				p := filepath.Join(root, e.Name())
				if !info.IsDir() {
					// plain file or symlink (link length only, never followed)
					s.files.Add(1)
					s.bytes.Add(info.Size())
					if info.Mode()&os.ModeSymlink == 0 {
						s.noteBig(p, info.Size())
					}
					ch <- result{i, &Node{Path: p, Name: e.Name(), Size: info.Size(), Files: 1}}
					continue
				}
				if skipDir(p) {
					continue
				}
				if n := s.walkDir(p, 1); n != nil {
					ch <- result{i, n}
				}
			}
		}()
	}
	wg.Wait()
	close(ch)
	for r := range ch {
		results = append(results, r)
	}
	sort.Slice(results, func(a, b int) bool { return results[a].idx < results[b].idx })
	for _, r := range results {
		rootNode.Size += r.node.Size
		rootNode.Files += r.node.Files
		rootNode.Dirs += r.node.Dirs
		if r.node.IsDir {
			rootNode.Dirs++
		}
		rootNode.Errs += r.node.Errs
		rootNode.Children = append(rootNode.Children, r.node)
	}
	prune(rootNode)
	return rootNode
}

// prune caps each directory's transported children, aggregating the
// remainder into one residual node so totals stay exact.
func prune(n *Node) {
	if n == nil || !n.IsDir {
		return
	}
	sort.SliceStable(n.Children, func(a, b int) bool { return n.Children[a].Size > n.Children[b].Size })
	for _, c := range n.Children {
		prune(c)
	}
	if len(n.Children) > maxChildren {
		kept := n.Children[:maxChildren]
		var restSize, restFiles, restDirs, restErrs int64
		restCount := int64(0)
		for _, c := range n.Children[maxChildren:] {
			restSize += c.Size
			restFiles += c.Files
			restDirs += c.Dirs
			restErrs += c.Errs
			restCount++
		}
		residual := &Node{
			Name:     fmt.Sprintf("… %d more items", restCount),
			Size:     restSize,
			Files:    restFiles,
			Dirs:     restDirs,
			Errs:     restErrs,
			Residual: true,
		}
		n.Children = append(append([]*Node{}, kept...), residual)
	}
}
