#!/usr/bin/env python3
"""Build a local structural knowledge graph for Ardur.

The graph is intentionally dependency-free and repo-local. It does not call
external AI services, embedding APIs, or networked indexers.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SUBSYSTEMS = {
    ".github": "GitHub automation",
    "deploy": "Deployment and cluster material",
    "docs": "Public docs, specs, ADRs, and articles",
    "examples": "Mission and framework examples",
    "go": "Go runtime, operator, credentials, governance",
    "media": "Selected public media assets",
    "python": "Python runtime, CLI, policy, receipts, tests",
}

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
GO_PACKAGE_RE = re.compile(r"^package\s+([A-Za-z_]\w*)", re.MULTILINE)
GO_FUNC_RE = re.compile(r"^func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*\(", re.MULTILINE)
GO_TYPE_RE = re.compile(r"^type\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*|struct|interface)", re.MULTILINE)
GO_IMPORT_BLOCK_RE = re.compile(r"import\s+\((.*?)\)", re.DOTALL)
GO_IMPORT_SINGLE_RE = re.compile(r'^\s*import\s+(?:[._A-Za-z0-9]+\s+)?"([^"]+)"', re.MULTILINE)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(cmd: list[str], cwd: Path, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def git_lines(root: Path, args: list[str]) -> list[str]:
    proc = run(["git", *args], root)
    if proc.returncode != 0:
        return []
    return [line for line in proc.stdout.splitlines() if line]


def git_one(root: Path, args: list[str], default: str = "unknown") -> str:
    lines = git_lines(root, args)
    return lines[0] if lines else default


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self._edge_keys: set[tuple[str, str, str]] = set()

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        path: str | None = None,
        **metadata: Any,
    ) -> None:
        if node_id in self.nodes:
            self.nodes[node_id]["metadata"].update({k: v for k, v in metadata.items() if v is not None})
            return
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "path": path,
            "metadata": {k: v for k, v in metadata.items() if v is not None},
        }

    def add_edge(self, source: str, target: str, edge_type: str, **metadata: Any) -> None:
        key = (source, target, edge_type)
        if key in self._edge_keys:
            return
        if source not in self.nodes or target not in self.nodes:
            return
        self._edge_keys.add(key)
        self.edges.append(
            {
                "source": source,
                "target": target,
                "type": edge_type,
                "metadata": {k: v for k, v in metadata.items() if v is not None},
            }
        )


def top_level(path: str) -> str:
    return path.split("/", 1)[0]


def classify_path(path: str) -> str:
    name = Path(path).name
    if path.startswith(".github/workflows/"):
        return "workflow"
    if path.startswith("docs/decisions/ADR-"):
        return "adr"
    if path.startswith("docs/specs/"):
        return "spec"
    if path.startswith("python/tests/") or path.endswith("_test.go"):
        return "test"
    if path.endswith(".py"):
        return "python-file"
    if path.endswith(".go"):
        return "go-file"
    if path.endswith(".md"):
        return "doc"
    if name in {"go.mod", "pyproject.toml", "Chart.yaml"}:
        return "manifest"
    if path.endswith((".yml", ".yaml", ".json", ".toml")):
        return "config"
    return "file"


def py_module_name(path: str) -> str | None:
    if not path.startswith("python/") or not path.endswith(".py"):
        return None
    rel = path.removeprefix("python/").removesuffix(".py")
    parts = rel.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(part for part in parts if part)


def resolve_relative_import(current: str, level: int, module: str | None) -> str | None:
    if level == 0:
        return module
    parts = current.split(".")
    keep = max(0, len(parts) - level)
    base = parts[:keep]
    if module:
        base.extend(module.split("."))
    return ".".join(part for part in base if part)


def walk_python(root: Path, graph: Graph, files: list[str], file_set: set[str]) -> None:
    module_to_id: dict[str, str] = {}
    for path in files:
        module = py_module_name(path)
        if module:
            node_id = f"py:{module}"
            module_to_id[module] = node_id
            graph.add_node(node_id, "python-module", module, path)
            graph.add_edge(f"file:{path}", node_id, "defines")

    for path in files:
        if not path.endswith(".py"):
            continue
        full_path = root / path
        module = py_module_name(path) or Path(path).stem
        try:
            tree = ast.parse(full_path.read_text(encoding="utf-8"), filename=path)
        except (SyntaxError, UnicodeDecodeError):
            graph.nodes[f"file:{path}"]["metadata"]["parse_error"] = True
            continue

        for item in ast.walk(tree):
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if getattr(item, "lineno", 0) <= 0:
                    continue
                qualname = item.name
                parent = getattr(item, "parent_class", None)
                if parent:
                    qualname = f"{parent}.{qualname}"
                symbol_type = "python-class" if isinstance(item, ast.ClassDef) else "python-function"
                symbol_id = f"py-symbol:{module}:{qualname}"
                graph.add_node(symbol_id, symbol_type, qualname, path, line=item.lineno, module=module)
                graph.add_edge(f"file:{path}", symbol_id, "defines")

            if isinstance(item, ast.ClassDef):
                for child in item.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        setattr(child, "parent_class", item.name)

        for item in ast.walk(tree):
            target_module: str | None = None
            if isinstance(item, ast.Import):
                for alias in item.names:
                    target_module = alias.name
                    if target_module in module_to_id:
                        graph.add_edge(f"py:{module}", module_to_id[target_module], "imports")
                    root_module = target_module.split(".")[0]
                    if root_module in module_to_id:
                        graph.add_edge(f"py:{module}", module_to_id[root_module], "imports")
            elif isinstance(item, ast.ImportFrom):
                target_module = resolve_relative_import(module, item.level, item.module)
                if target_module in module_to_id:
                    graph.add_edge(f"py:{module}", module_to_id[target_module], "imports")

        if path.startswith("python/tests/test_"):
            candidate = path.removeprefix("python/tests/test_").removesuffix(".py")
            target = f"python/vibap/{candidate}.py"
            if target in file_set:
                graph.add_edge(f"file:{path}", f"file:{target}", "tests")
                target_module = py_module_name(target)
                if target_module:
                    graph.add_edge(f"file:{path}", f"py:{target_module}", "tests")


def go_mod_info(root: Path) -> tuple[str | None, str | None]:
    go_mod = root / "go" / "go.mod"
    if not go_mod.exists():
        return None, None
    module_path = None
    go_version = None
    for line in go_mod.read_text(encoding="utf-8").splitlines():
        if line.startswith("module "):
            module_path = line.split()[1]
        elif line.startswith("go "):
            go_version = line.split()[1]
    return module_path, go_version


def version_tuple(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    return tuple(int(part) for part in value.split(".") if part.isdigit())


def local_go_version(root: Path) -> str | None:
    proc = run(["go", "version"], root, timeout=5)
    if proc.returncode != 0:
        return None
    match = re.search(r"go([0-9]+(?:\.[0-9]+)+)", proc.stdout)
    return match.group(1) if match else None


def decode_json_stream(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    idx = 0
    objects: list[dict[str, Any]] = []
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        obj, idx = decoder.raw_decode(text, idx)
        if isinstance(obj, dict):
            objects.append(obj)
    return objects


def receiver_name(raw: str | None) -> str | None:
    if not raw:
        return None
    token = raw.strip().split()[-1]
    token = token.lstrip("*")
    return token.split("[", 1)[0]


def go_imports_from_text(text: str) -> set[str]:
    imports: set[str] = set(GO_IMPORT_SINGLE_RE.findall(text))
    for block in GO_IMPORT_BLOCK_RE.findall(text):
        imports.update(re.findall(r'"([^"]+)"', block))
    return imports


def walk_go(root: Path, graph: Graph, files: list[str]) -> None:
    go_files = [path for path in files if path.startswith("go/") and path.endswith(".go")]
    if not go_files:
        return

    module_path, required_go = go_mod_info(root)
    actual_go = local_go_version(root)
    package_dirs = sorted({str(Path(path).parent) for path in go_files})
    dir_to_pkg_id = {directory: f"go-pkg:{directory}" for directory in package_dirs}

    for directory, pkg_id in dir_to_pkg_id.items():
        label = "./" + directory.removeprefix("go/")
        if label == "./":
            label = "./go"
        graph.add_node(pkg_id, "go-package", label, directory)
        graph.add_edge(f"subsystem:{top_level(directory)}", pkg_id, "contains")

    go_list_used = False
    go_dir = root / "go"
    if (
        go_dir.exists()
        and module_path
        and actual_go
        and (not required_go or version_tuple(actual_go) >= version_tuple(required_go))
    ):
        proc = run(["go", "list", "-json", "-mod=readonly", "./..."], go_dir, timeout=25)
        if proc.returncode == 0:
            go_list_used = True
            for package in decode_json_stream(proc.stdout):
                package_dir = package.get("Dir")
                import_path = package.get("ImportPath")
                if not package_dir or not import_path:
                    continue
                try:
                    rel_dir = str(Path(package_dir).resolve().relative_to(root.resolve()))
                except ValueError:
                    continue
                pkg_id = f"go-pkg:{rel_dir}"
                graph.add_node(pkg_id, "go-package", import_path, rel_dir, source="go-list")
                dir_to_pkg_id[rel_dir] = pkg_id
                for import_name in package.get("Imports", []):
                    if module_path and import_name.startswith(module_path):
                        suffix = import_name.removeprefix(module_path).lstrip("/")
                        target_dir = "go" if not suffix else f"go/{suffix}"
                graph.add_edge(pkg_id, f"go-pkg:{target_dir}", "imports", detected_by="go-list")

    for path in go_files:
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        directory = str(Path(path).parent)
        pkg_id = dir_to_pkg_id[directory]
        package_match = GO_PACKAGE_RE.search(text)
        package_name = package_match.group(1) if package_match else Path(directory).name
        graph.nodes[pkg_id]["metadata"].setdefault("package_name", package_name)
        graph.nodes[pkg_id]["metadata"].setdefault("go_list_used", go_list_used)
        if required_go and actual_go and version_tuple(actual_go) < version_tuple(required_go):
            graph.nodes[pkg_id]["metadata"].setdefault(
                "go_list_skipped",
                f"local Go {actual_go} is below go/go.mod requirement {required_go}",
            )
        graph.add_edge(pkg_id, f"file:{path}", "contains")

        if not go_list_used and module_path:
            for import_name in go_imports_from_text(text):
                if import_name.startswith(module_path):
                    suffix = import_name.removeprefix(module_path).lstrip("/")
                    target_dir = "go" if not suffix else f"go/{suffix}"
                    graph.add_edge(pkg_id, f"go-pkg:{target_dir}", "imports", detected_by="regex")

        for receiver, name in GO_FUNC_RE.findall(text):
            recv = receiver_name(receiver)
            label = f"{recv}.{name}" if recv else name
            symbol_id = f"go-symbol:{directory}:{label}"
            graph.add_node(symbol_id, "go-function", label, path, package=package_name)
            graph.add_edge(f"file:{path}", symbol_id, "defines")
            graph.add_edge(pkg_id, symbol_id, "defines")

        for name, kind in GO_TYPE_RE.findall(text):
            symbol_id = f"go-symbol:{directory}:{name}"
            graph.add_node(symbol_id, "go-type", name, path, package=package_name, kind=kind)
            graph.add_edge(f"file:{path}", symbol_id, "defines")
            graph.add_edge(pkg_id, symbol_id, "defines")

        if path.endswith("_test.go"):
            graph.add_edge(f"file:{path}", pkg_id, "tests")
            sibling = path.removesuffix("_test.go") + ".go"
            if (root / sibling).exists():
                graph.add_edge(f"file:{path}", f"file:{sibling}", "tests")


def walk_markdown_refs(root: Path, graph: Graph, files: list[str], file_set: set[str]) -> None:
    root_resolved = root.resolve()
    for path in files:
        if not path.endswith(".md"):
            continue
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        for raw_target in MARKDOWN_LINK_RE.findall(text):
            target = raw_target.split("#", 1)[0].strip()
            if (
                not target
                or target.startswith(("http://", "https://", "mailto:"))
                or target.startswith("#")
            ):
                continue
            candidate = ((root / path).parent / target).resolve()
            try:
                rel = str(candidate.relative_to(root_resolved))
            except ValueError:
                continue
            if rel in file_set:
                graph.add_edge(f"file:{path}", f"file:{rel}", "references")


def add_workflow_edges(graph: Graph, files: list[str]) -> None:
    for path in files:
        if not path.startswith(".github/workflows/"):
            continue
        name = Path(path).name
        workflow_id = f"file:{path}"
        if name == "tests.yml":
            graph.add_edge(workflow_id, "subsystem:python", "workflow-runs", job="python")
            graph.add_edge(workflow_id, "subsystem:go", "workflow-runs", job="go")
        elif name == "codeql.yml":
            graph.add_edge(workflow_id, "subsystem:python", "workflow-runs", job="codeql")
            graph.add_edge(workflow_id, "subsystem:go", "workflow-runs", job="codeql")
        elif name == "validate-formats.yml":
            graph.add_edge(workflow_id, "repo:ardur", "validates", validates_target="json-yaml-schema")
        elif name == "secret-scan.yml":
            graph.add_edge(workflow_id, "repo:ardur", "validates", validates_target="secrets-and-public-terms")
        elif name == "link-check.yml":
            graph.add_edge(workflow_id, "subsystem:docs", "validates", validates_target="markdown-links")


def build_graph(root: Path, *, base: str = "origin/dev") -> dict[str, Any]:
    tracked_files = git_lines(root, ["ls-files"])
    untracked_files = git_lines(root, ["ls-files", "--others", "--exclude-standard"])
    files = sorted(dict.fromkeys([*tracked_files, *untracked_files]))
    tracked_set = set(tracked_files)
    untracked_set = set(untracked_files)

    if not files:
        files = sorted(
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file()
            and ".git" not in path.parts
            and ".context" not in path.parts
            and "__pycache__" not in path.parts
        )
        tracked_set = set(files)
        untracked_set = set()
    file_set = set(files)

    graph = Graph()
    graph.add_node("repo:ardur", "repo", "Ardur", None)
    for subsystem, description in SUBSYSTEMS.items():
        graph.add_node(f"subsystem:{subsystem}", "subsystem", subsystem, subsystem, description=description)
        graph.add_edge("repo:ardur", f"subsystem:{subsystem}", "contains")

    for path in files:
        node_type = classify_path(path)
        graph.add_node(
            f"file:{path}",
            node_type,
            path,
            path,
            subsystem=top_level(path),
            tracked=path in tracked_set,
            untracked=path in untracked_set,
        )
        parent = f"subsystem:{top_level(path)}"
        if parent in graph.nodes:
            graph.add_edge(parent, f"file:{path}", "contains")
        else:
            graph.add_edge("repo:ardur", f"file:{path}", "contains")

    walk_python(root, graph, files, file_set)
    walk_go(root, graph, files)
    walk_markdown_refs(root, graph, files, file_set)
    add_workflow_edges(graph, files)

    nodes = sorted(graph.nodes.values(), key=lambda node: node["id"])
    edges = sorted(graph.edges, key=lambda edge: (edge["source"], edge["type"], edge["target"]))
    return {
        "schema_version": "ardur.graph.v1",
        "generated_at": utc_now(),
        "repo": {
            "root": str(root),
            "branch": git_one(root, ["branch", "--show-current"]),
            "head": git_one(root, ["rev-parse", "--short", "HEAD"]),
            "base": base,
            "tracked_file_count": len(tracked_set),
            "untracked_file_count": len(untracked_set),
            "indexed_file_count": len(files),
        },
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "nodes_by_type": dict(sorted(Counter(node["type"] for node in nodes).items())),
            "edges_by_type": dict(sorted(Counter(edge["type"] for edge in edges).items())),
        },
        "nodes": nodes,
        "edges": edges,
    }


def markdown_summary(graph: dict[str, Any]) -> str:
    nodes = graph["nodes"]
    edges = graph["edges"]
    counts = graph["counts"]
    subsystem_counts: dict[str, int] = defaultdict(int)
    symbol_counts: Counter[str] = Counter()

    node_by_id = {node["id"]: node for node in nodes}
    for node in nodes:
        subsystem = node["metadata"].get("subsystem")
        if subsystem:
            subsystem_counts[subsystem] += 1
    for edge in edges:
        if edge["type"] == "defines" and edge["target"] in node_by_id:
            target_type = node_by_id[edge["target"]]["type"]
            if target_type in {"python-class", "python-function", "go-function", "go-type"}:
                symbol_counts[edge["source"]] += 1

    lines = [
        "# Ardur Knowledge Graph",
        "",
        f"Generated: `{graph['generated_at']}`",
        f"Branch: `{graph['repo']['branch']}`",
        f"HEAD: `{graph['repo']['head']}`",
        f"Base: `{graph['repo']['base']}`",
        "",
        "## Counts",
        "",
        f"- Nodes: `{counts['nodes']}`",
        f"- Edges: `{counts['edges']}`",
        f"- Indexed files: `{graph['repo']['indexed_file_count']}`",
        f"- Tracked files: `{graph['repo']['tracked_file_count']}`",
        f"- Untracked nonignored files: `{graph['repo']['untracked_file_count']}`",
        "",
        "## Subsystems",
        "",
    ]
    for subsystem in sorted(SUBSYSTEMS):
        lines.append(f"- `{subsystem}`: {subsystem_counts.get(subsystem, 0)} indexed files")

    lines.extend(["", "## Node Types", ""])
    for node_type, count in counts["nodes_by_type"].items():
        lines.append(f"- `{node_type}`: {count}")

    lines.extend(["", "## Edge Types", ""])
    for edge_type, count in counts["edges_by_type"].items():
        lines.append(f"- `{edge_type}`: {count}")

    lines.extend(["", "## High-Signal Entrypoints", ""])
    for path in [
        "AGENTS.md",
        "README.md",
        "STATUS.md",
        "docs/agent-instructions/README.md",
        "docs/agent-instructions/shared.md",
        "docs/conductor-bootstrap.md",
        "docs/engineering-standards.md",
        "docs/TESTING.md",
        "docs/public-import-plan.md",
        ".github/workflows/tests.yml",
        "python/pyproject.toml",
        "go/go.mod",
    ]:
        node_id = f"file:{path}"
        if node_id in node_by_id:
            lines.append(f"- `{path}`")

    lines.extend(["", "## Symbol-Dense Files", ""])
    for node_id, count in symbol_counts.most_common(20):
        path = node_by_id[node_id]["path"] or node_by_id[node_id]["label"]
        lines.append(f"- `{path}`: {count} symbols")

    lines.extend(
        [
            "",
            "## Usage",
            "",
            "- Start with this summary for a human-readable map.",
            "- Use `ardur-graph.json` for exact nodes and edges.",
            "- Use `rg` for task-specific deep dives after identifying graph neighborhoods.",
        ]
    )
    return "\n".join(lines) + "\n"


def mermaid_summary(graph: dict[str, Any]) -> str:
    nodes = graph["nodes"]
    subsystem_counts: dict[str, int] = defaultdict(int)
    for node in nodes:
        subsystem = node["metadata"].get("subsystem")
        if subsystem:
            subsystem_counts[subsystem] += 1

    lines = [
        "flowchart TD",
        '  repo["Ardur repo"]',
    ]
    for subsystem in sorted(SUBSYSTEMS):
        safe = subsystem.replace(".", "dot").replace("-", "_")
        label = f"{subsystem}<br/>{subsystem_counts.get(subsystem, 0)} files"
        lines.append(f'  sub_{safe}["{label}"]')
        lines.append(f"  repo --> sub_{safe}")
    lines.extend(
        [
            '  boot["Conductor bootstrap"]',
            '  graph[".context graph index"]',
            '  tests["tests.yml"]',
            "  boot --> graph",
            "  boot --> repo",
            "  tests --> sub_python",
            "  tests --> sub_go",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Ardur structural knowledge graph.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, default=Path(".context"))
    parser.add_argument("--base", default="origin/dev", help="default integration base to record in the graph")
    args = parser.parse_args()

    root = args.repo_root.resolve()
    output_dir = args.output_dir
    if not output_dir.is_absolute():
        output_dir = root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    graph = build_graph(root, base=args.base)
    json_path = output_dir / "ardur-graph.json"
    md_path = output_dir / "ardur-graph.md"
    mmd_path = output_dir / "ardur-graph.mmd"

    json_path.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(markdown_summary(graph), encoding="utf-8")
    mmd_path.write_text(mermaid_summary(graph), encoding="utf-8")

    print(f"wrote {json_path.relative_to(root)}")
    print(f"wrote {md_path.relative_to(root)}")
    print(f"wrote {mmd_path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
