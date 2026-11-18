"""区间代数测试：期望值全部手工给定，并用逐点集合做独立交叉验证。"""
import unittest

from solution.intervals import (
    Piece, intersect, merge, subtract, contains, overlaps,
    sweep_tagged, intersect_tagged, subtract_tagged, tagged_to_intervals,
)


def points(intervals):
    out = set()
    for lo, hi in intervals:
        out.update(range(lo, hi + 1))
    return out


class TestPlainIntervals(unittest.TestCase):
    def test_merge_adjacent_closed_intervals(self):
        # 闭区间 [1,2] 与 [3,4] 相邻，应合并为 [1,4]
        self.assertEqual(merge([(1, 2), (3, 4)]), [(1, 4)])            # 相邻融合
        self.assertEqual(merge([(5, 6), (1, 3)]), [(1, 3), (5, 6)])    # 排序后不相邻
        self.assertEqual(merge([(1, 2), (4, 5)]), [(1, 2), (4, 5)])    # 不相邻，保留两段

    def test_intersect_hand_values(self):
        self.assertEqual(intersect([(1, 10)], [(4, 6)]), [(4, 6)])
        self.assertEqual(intersect([(1, 4), (8, 10)], [(3, 9)]), [(3, 4), (8, 9)])
        self.assertEqual(intersect([(1, 5)], [(6, 8)]), [])

    def test_subtract_hand_values(self):
        self.assertEqual(subtract([(1, 10)], [(4, 6)]), [(1, 3), (7, 10)])
        self.assertEqual(subtract([(1, 10)], [(1, 10)]), [])
        self.assertEqual(subtract([(1, 10)], [(10, 10)]), [(1, 9)])
        # 单端口挖除（边界）
        self.assertEqual(subtract([(1, 3)], [(2, 2)]), [(1, 1), (3, 3)])

    def test_contains_and_overlaps(self):
        self.assertTrue(contains([(1, 10)], 4, 6))
        self.assertFalse(contains([(1, 4), (8, 10)], 4, 8))
        self.assertTrue(overlaps([(1, 4)], 4, 9))   # 闭区间端点相交
        self.assertFalse(overlaps([(1, 4)], 5, 9))

    def test_set_equivalence_against_point_sets(self):
        a = [(1, 12), (20, 30)]
        b = [(5, 22), (29, 40)]
        self.assertEqual(points(intersect(a, b)), points(a) & points(b))
        self.assertEqual(points(subtract(a, b)), points(a) - points(b))
        self.assertEqual(points(merge([(3, 7), (8, 9), (15, 15)])),
                         points([(3, 9), (15, 15)]))


class TestSweepTagged(unittest.TestCase):
    def test_single_allow(self):
        pieces = sweep_tagged([((10, 100), True, "r")])
        self.assertEqual(pieces, [Piece(10, 100, frozenset({"r"}))])

    def test_deny_takes_precedence_even_with_allow(self):
        # 允许 [1,100] 覆盖拒绝 [25,25]，拒绝优先，25 被挖空
        pieces = sweep_tagged([((1, 100), True, "a"), ((25, 25), False, "d")])
        iv = tagged_to_intervals(pieces)
        self.assertEqual(iv, [(1, 24), (26, 100)])
        self.assertEqual(points(iv), set(range(1, 101)) - {25})

    def test_overlapping_allows_keep_both_citations(self):
        pieces = sweep_tagged([
            ((1, 10), True, "a"), ((5, 15), True, "b"), ((7, 7), False, "d"),
        ])
        as_map = {(p.lo, p.hi): set(p.tags) for p in pieces}
        self.assertEqual(as_map[(1, 4)], {"a"})
        self.assertEqual(as_map[(5, 6)], {"a", "b"})
        self.assertEqual(as_map[(8, 10)], {"a", "b"})
        self.assertEqual(as_map[(11, 15)], {"b"})
        # 出处片段并集的端口集合等于朴素允许集减拒绝集
        expect = (set(range(1, 11)) | set(range(5, 16))) - {7}
        self.assertEqual(points(tagged_to_intervals(pieces)), expect)

    def test_adjacent_same_tags_fused(self):
        # 同标签的两条相邻允许规则融合为一个片段
        pieces = sweep_tagged([((1, 5), True, "a"), ((6, 10), True, "a")])
        self.assertEqual(len(pieces), 1)
        self.assertEqual((pieces[0].lo, pieces[0].hi), (1, 10))

    def test_adjacent_different_tags_kept_separate(self):
        # 标签不同的相邻片段不得融合
        pieces = sweep_tagged([((1, 5), True, "a"), ((6, 10), True, "b")])
        self.assertEqual(len(pieces), 2)
        self.assertEqual([(p.lo, p.hi) for p in pieces], [(1, 5), (6, 10)])

    def test_intersect_tagged_combines_citations(self):
        left = sweep_tagged([((1, 10), True, "out")])
        right = sweep_tagged([((4, 12), True, "in")])
        pieces = intersect_tagged(left, right, lambda x, y: x | y)
        self.assertEqual(tagged_to_intervals(pieces), [(4, 10)])
        self.assertEqual(set(pieces[0].tags), {"out", "in"})

    def test_subtract_tagged_preserves_tags(self):
        pieces = sweep_tagged([((1, 10), True, "r")])
        cut = subtract_tagged(pieces, [(4, 6)])
        self.assertEqual(tagged_to_intervals(cut), [(1, 3), (7, 10)])
        self.assertTrue(all(p.tags == frozenset({"r"}) for p in cut))


if __name__ == "__main__":
    unittest.main()
