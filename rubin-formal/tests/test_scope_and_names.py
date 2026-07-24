"""Tests for scope management and name qualification in check_formal_registry_truth."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_formal_registry_truth import (
    ScopeFrame,
    _current_namespace_parts,
    _pop_scope,
    _qualify_decl_name,
    extract_declared_names,
)


class CurrentNamespacePartsTests(unittest.TestCase):
    def test_empty_stack(self) -> None:
        self.assertEqual(_current_namespace_parts([]), [])

    def test_single_namespace(self) -> None:
        stack = [ScopeFrame("namespace", "Foo", ("Foo",))]
        self.assertEqual(_current_namespace_parts(stack), ["Foo"])

    def test_nested_namespaces(self) -> None:
        stack = [
            ScopeFrame("namespace", "Foo", ("Foo",)),
            ScopeFrame("namespace", "Bar", ("Bar",)),
        ]
        self.assertEqual(_current_namespace_parts(stack), ["Foo", "Bar"])

    def test_sections_ignored(self) -> None:
        stack = [
            ScopeFrame("namespace", "Foo", ("Foo",)),
            ScopeFrame("section", "MySection", ()),
        ]
        self.assertEqual(_current_namespace_parts(stack), ["Foo"])

    def test_dotted_namespace(self) -> None:
        stack = [ScopeFrame("namespace", "Foo.Bar", ("Foo", "Bar"))]
        self.assertEqual(_current_namespace_parts(stack), ["Foo", "Bar"])

    def test_mixed_namespace_and_section(self) -> None:
        stack = [
            ScopeFrame("namespace", "A", ("A",)),
            ScopeFrame("section", "S", ()),
            ScopeFrame("namespace", "B", ("B",)),
        ]
        self.assertEqual(_current_namespace_parts(stack), ["A", "B"])


class QualifyDeclNameTests(unittest.TestCase):
    def test_no_namespace(self) -> None:
        self.assertEqual(_qualify_decl_name("foo", []), "foo")

    def test_with_namespace(self) -> None:
        self.assertEqual(_qualify_decl_name("bar", ["Foo"]), "Foo.bar")

    def test_with_nested_namespace(self) -> None:
        self.assertEqual(_qualify_decl_name("baz", ["Foo", "Bar"]), "Foo.Bar.baz")

    def test_root_prefix_strips_namespace(self) -> None:
        self.assertEqual(_qualify_decl_name("_root_.Global.foo", ["A", "B"]), "Global.foo")

    def test_root_prefix_no_namespace(self) -> None:
        self.assertEqual(_qualify_decl_name("_root_.TopLevel", []), "TopLevel")

    def test_dotted_local_name(self) -> None:
        self.assertEqual(_qualify_decl_name("Sub.name", ["NS"]), "NS.Sub.name")


class PopScopeTests(unittest.TestCase):
    def test_pop_empty_stack(self) -> None:
        stack: list[ScopeFrame] = []
        _pop_scope(stack, None)
        self.assertEqual(stack, [])

    def test_pop_unnamed(self) -> None:
        stack = [ScopeFrame("section", None, ())]
        _pop_scope(stack, None)
        self.assertEqual(stack, [])

    def test_pop_named_matching(self) -> None:
        stack = [
            ScopeFrame("namespace", "A", ("A",)),
            ScopeFrame("namespace", "B", ("B",)),
        ]
        _pop_scope(stack, "A")
        self.assertEqual(stack, [])

    def test_pop_named_non_matching(self) -> None:
        stack = [ScopeFrame("namespace", "A", ("A",))]
        _pop_scope(stack, "X")
        # when no matching label found, pops the last frame
        self.assertEqual(stack, [])

    def test_pop_named_from_middle(self) -> None:
        stack = [
            ScopeFrame("namespace", "A", ("A",)),
            ScopeFrame("section", "S", ()),
            ScopeFrame("namespace", "B", ("B",)),
        ]
        _pop_scope(stack, "S")
        self.assertEqual(len(stack), 1)
        self.assertEqual(stack[0].label, "A")

    def test_pop_leaves_earlier_frames(self) -> None:
        stack = [
            ScopeFrame("namespace", "A", ("A",)),
            ScopeFrame("namespace", "B", ("B",)),
        ]
        _pop_scope(stack, "B")
        self.assertEqual(len(stack), 1)
        self.assertEqual(stack[0].label, "A")


class ExtractDeclNamesEdgeCaseTests(unittest.TestCase):
    """Additional edge-case tests for extract_declared_names beyond the 3 existing tests."""

    def test_section_does_not_add_to_namespace(self) -> None:
        text = """
namespace Foo
section MySection
theorem inside_section : True := by trivial
end MySection
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.inside_section", names)

    def test_private_theorem(self) -> None:
        text = """
namespace Foo
private theorem secret : True := by trivial
end Foo
"""
        names = extract_declared_names(text)
        self.assertNotIn("Foo.secret", names)

    def test_protected_theorem(self) -> None:
        text = """
namespace Foo
protected theorem guarded : True := by trivial
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.guarded", names)

    def test_noncomputable_def(self) -> None:
        text = """
namespace Foo
noncomputable def myDef : Nat := 0
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.myDef", names)

    def test_abbrev_declaration(self) -> None:
        text = """
namespace Foo
abbrev MyType := Nat
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.MyType", names)

    def test_lemma_declaration(self) -> None:
        text = """
namespace Foo
lemma my_lemma : True := by trivial
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.my_lemma", names)

    def test_no_namespace(self) -> None:
        text = "theorem top_level : True := by trivial"
        names = extract_declared_names(text)
        self.assertIn("top_level", names)

    def test_root_prefix_overrides_namespace(self) -> None:
        text = """
namespace Foo
theorem _root_.Global.bar : True := by trivial
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Global.bar", names)
        self.assertNotIn("Foo.Global.bar", names)

    def test_attribute_annotation_before_theorem(self) -> None:
        text = """
namespace Foo
@[simp] theorem simp_lemma : True := by trivial
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.simp_lemma", names)

    def test_empty_text(self) -> None:
        self.assertEqual(extract_declared_names(""), set())

    def test_only_namespace_no_decl(self) -> None:
        text = """
namespace Foo
end Foo
"""
        self.assertEqual(extract_declared_names(text), set())

    def test_nested_namespaces(self) -> None:
        text = """
namespace A
namespace B
theorem deep : True := by trivial
end B
end A
"""
        names = extract_declared_names(text)
        self.assertIn("A.B.deep", names)

    def test_reopened_namespace(self) -> None:
        text = """
namespace Foo
theorem first : True := by trivial
end Foo
namespace Foo
theorem second : True := by trivial
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.first", names)
        self.assertIn("Foo.second", names)

    def test_unsafe_partial_modifiers(self) -> None:
        text = """
namespace Foo
unsafe def unsafeFn : Nat := 0
partial def partialFn : Nat := 0
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.unsafeFn", names)
        self.assertIn("Foo.partialFn", names)

    def test_special_chars_in_names(self) -> None:
        text = """
namespace Foo
theorem name?_with!_special : True := by trivial
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.name?_with!_special", names)

    def test_multiple_declarations_same_namespace(self) -> None:
        text = """
namespace Foo
theorem a : True := by trivial
lemma b : True := by trivial
def c : Nat := 0
abbrev d := Nat
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.a", names)
        self.assertIn("Foo.b", names)
        self.assertIn("Foo.c", names)
        self.assertIn("Foo.d", names)

    def test_unnamed_section(self) -> None:
        text = """
namespace Foo
section
theorem inside : True := by trivial
end
end Foo
"""
        names = extract_declared_names(text)
        self.assertIn("Foo.inside", names)


if __name__ == "__main__":
    unittest.main()
