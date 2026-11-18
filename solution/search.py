"""切换序列搜索。

状态用位掩码表示：第 i 位对应字典序第 i 个组，1 表示已切换到目标规则。
- 合法邻接：切换一个尚未切换、且其全部前置组均已切换的组；
- 合法状态：通过全部 required/forbidden 约束（初始状态 0 与全量状态
  ``(1<<n)-1`` 同样参与校验）；
- 目标：从 0 到全量掩码的字典序最小合法序列；
- 无解：报告完成组数量最多的可达合法状态，并列时按完成组排序列表
  （即组名排序后的元组）字典序打破，并给出该状态每个下一步的阻断证据。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Spec
from .policy import Auditor, Violation


@dataclass
class NextStepBlock:
    """最佳死路状态上某个候选下一步的阻断证据。"""

    group: str
    reachable: bool
    reason: str                       # dependency | constraint | dead_end
    missing_prerequisites: list[str] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)


@dataclass
class SearchResult:
    found: bool
    sequence: list[str]               # found=True 时为字典序最小合法序列
    reachable_states: list[int]       # 全部可达合法状态（掩码）
    best_mask: int                    # 无解时的最佳可达状态
    best_completed: list[str]         # 该状态完成组（字典序）
    next_step_blocks: list[NextStepBlock]


class Planner:
    def __init__(self, spec: Spec, auditor: Auditor | None = None) -> None:
        self.spec = spec
        self.auditor = auditor or Auditor(spec)
        self.n = len(spec.groups)
        self.index = {g: i for i, g in enumerate(spec.groups)}
        self.prereq_mask = {
            g: sum(1 << self.index[p] for p in spec.depends_on.get(g, frozenset()))
            for g in spec.groups
        }
        self._valid_cache: dict[int, bool] = {}

    # ------------------------------------------------------------------ #
    def is_valid(self, mask: int) -> bool:
        if mask not in self._valid_cache:
            self._valid_cache[mask] = self.auditor.is_valid(mask)
        return self._valid_cache[mask]

    def available_groups(self, mask: int) -> list[str]:
        """当前状态下满足 DAG 前置、尚未切换的候选组（字典序）。"""
        out = []
        for g in self.spec.groups:
            bit = 1 << self.index[g]
            if mask & bit:
                continue
            if self.prereq_mask[g] & ~mask == 0:
                out.append(g)
        return out

    def enumerate_reachable(self) -> list[int]:
        """BFS 枚举全部可达的合法状态。"""
        reachable: set[int] = set()
        queue = [0]
        reachable.add(0)
        head = 0
        while head < len(queue):
            mask = queue[head]
            head += 1
            for g in self.available_groups(mask):
                nxt = mask | (1 << self.index[g])
                if nxt in reachable or not self.is_valid(nxt):
                    continue
                reachable.add(nxt)
                queue.append(nxt)
        return sorted(reachable)

    # ------------------------------------------------------------------ #
    def solve(self) -> SearchResult:
        if not self.is_valid(0):
            # 初始状态即违规：没有任何可达状态。
            return self._no_plan(reachable=[0], forced_mask=0)
        full = self.spec.full_mask
        reachable = self.enumerate_reachable()

        # 字典序最小：按组名字典序深度优先，第一个到达全量的路径即答案。
        memo_bad: set[int] = set()

        def dfs(mask: int, path: list[str]) -> list[str] | None:
            if mask == full:
                return list(path)
            if mask in memo_bad:
                return None
            for g in self.available_groups(mask):
                nxt = mask | (1 << self.index[g])
                if not self.is_valid(nxt) or nxt in memo_bad:
                    continue
                path.append(g)
                answer = dfs(nxt, path)
                if answer is not None:
                    return answer
                path.pop()
            memo_bad.add(mask)
            return None

        answer = dfs(0, [])
        if answer is not None:
            return SearchResult(
                found=True,
                sequence=answer,
                reachable_states=reachable,
                best_mask=full,
                best_completed=list(self.spec.groups),
                next_step_blocks=[],
            )
        return self._no_plan(reachable=reachable)

    # ------------------------------------------------------------------ #
    def _no_plan(self, reachable: list[int], forced_mask: int | None = None) -> SearchResult:
        if forced_mask is not None:
            best = forced_mask
        else:
            best = self._pick_best(reachable)
        blocks = self._block_evidence(best, set(reachable))
        return SearchResult(
            found=False,
            sequence=[],
            reachable_states=reachable,
            best_mask=best,
            best_completed=self._completed(best),
            next_step_blocks=blocks,
        )

    def _pick_best(self, reachable: list[int]) -> int:
        """完成组最多；并列时按完成组排序列表的字典序。"""
        def key(mask: int) -> tuple[int, list[str]]:
            return (-mask.bit_count(), self._completed(mask))

        return min(reachable, key=key)

    def _completed(self, mask: int) -> list[str]:
        return [g for i, g in enumerate(self.spec.groups) if (mask >> i) & 1]

    def _block_evidence(self, mask: int, reachable: set[int]) -> list[NextStepBlock]:
        """最佳状态上每个未切换组的下一步阻断证据（按组名字典序）。"""
        blocks: list[NextStepBlock] = []
        for g in self.spec.groups:
            bit = 1 << self.index[g]
            if mask & bit:
                continue
            missing = [
                p for p in sorted(self.spec.depends_on.get(g, frozenset()))
                if not ((mask >> self.index[p]) & 1)
            ]
            if missing:
                blocks.append(NextStepBlock(
                    group=g, reachable=False, reason="dependency",
                    missing_prerequisites=missing,
                ))
                continue
            nxt = mask | bit
            # 最佳态是全部可达合法状态中 popcount 最大者；其任何合法邻接的
            # popcount 必然更大，不可能不可达——否则它已取代最佳态。因此走到
            # 这里的 nxt 一定违规，原因只会是 constraint，不存在 dead_end 分支。
            if not self.is_valid(nxt):
                blocks.append(NextStepBlock(
                    group=g, reachable=False, reason="constraint",
                    violations=self.auditor.violations(nxt),
                ))
                continue
            # 理论不可达：合法邻接必已进入可达集并成为更优最佳态。
            blocks.append(NextStepBlock(
                group=g, reachable=True, reason="dead_end",
                violations=[],
            ))
        return blocks
