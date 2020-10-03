import functools
import sys

from wacryptolib.error_handling import (
    gather_exception_subclasses,
    construct_status_slugs_mapper,
    slugify_exception_class,
    get_closest_exception_class_for_status_slugs,
    _fully_qualified_name,
    StatusSlugsMapper,
)

LookupError = LookupError
IOError = IOError


class MyRuntimeError(RuntimeError):
    pass


class MyExc(Exception):
    pass


class MyExcOther(Exception):
    pass


class MyExcChild1(MyExc):
    pass


class MyExcChild2(MyExc):
    pass


class MyExcChild1GrandChild(MyExcChild1):
    pass


def test_status_slugs_utilities():

    this_module = sys.modules[MyExc.__module__]

    selected_classes = gather_exception_subclasses(module=this_module, parent_classes=MyExc)
    assert set(selected_classes) == set([MyExc, MyExcChild1, MyExcChild2, MyExcChild1GrandChild]), selected_classes

    assert _fully_qualified_name(LookupError) == "LookupError"  # Builtins don't keep their module prefix
    assert _fully_qualified_name(MyExc) == "test_wacryptolib_error_handling.MyExc"

    mapper_tree = construct_status_slugs_mapper(selected_classes, fallback_exception_class=NotImplementedError)
    # from pprint import pprint ; pprint(mapper)
    assert mapper_tree == {
        "": NotImplementedError,
        "test_wacryptolib_error_handling.MyExc": {
            "": MyExc,
            "test_wacryptolib_error_handling.MyExcChild1": {
                "": MyExcChild1,
                "test_wacryptolib_error_handling.MyExcChild1GrandChild": {"": MyExcChild1GrandChild},
            },
            "test_wacryptolib_error_handling.MyExcChild2": {"": MyExcChild2},
        },
    }

    selected_classes = gather_exception_subclasses(module=this_module, parent_classes=(EnvironmentError, RuntimeError))
    assert set(selected_classes) == set([IOError, MyRuntimeError]), selected_classes

    selected_classes = gather_exception_subclasses(module=this_module, parent_classes=(UnicodeError,))
    assert set(selected_classes) == set(), selected_classes

    assert slugify_exception_class(Exception) == [], slugify_exception_class(Exception)

    assert slugify_exception_class(MyExcChild1GrandChild) == [
        "test_wacryptolib_error_handling.MyExc",
        "test_wacryptolib_error_handling.MyExcChild1",
        "test_wacryptolib_error_handling.MyExcChild1GrandChild",
    ], slugify_exception_class(MyExcChild1GrandChild)

    assert get_closest_exception_class_for_status_slugs((), mapper_tree=mapper_tree) == NotImplementedError

    assert get_closest_exception_class_for_status_slugs(("XYZ", "ZXY"), mapper_tree=mapper_tree) == NotImplementedError

    status_slug = ("test_wacryptolib_error_handling.MyExc", "test_wacryptolib_error_handling.MyExcChild1")
    assert get_closest_exception_class_for_status_slugs(status_slug, mapper_tree=mapper_tree) == MyExcChild1

    status_slug = (
        "test_wacryptolib_error_handling.MyExc",
        "test_wacryptolib_error_handling.XXXXXXXX",
        "test_wacryptolib_error_handling.YYYYYYYY",
    )
    assert (
        get_closest_exception_class_for_status_slugs(status_slug, mapper_tree=mapper_tree)
        == MyExc  # closest ancestor found
    )

    # Test the case of not-included ancestor exception classes

    mapper_tree = construct_status_slugs_mapper([KeyError], fallback_exception_class=RuntimeError)
    assert (
        get_closest_exception_class_for_status_slugs(["LookupError", "KeyError"], mapper_tree=mapper_tree) == KeyError
    )

    assert (
        get_closest_exception_class_for_status_slugs(["LookupError"], mapper_tree=mapper_tree)
        == RuntimeError  # No fallback on some auto-created LookupError entry
    )

    assert get_closest_exception_class_for_status_slugs(["OSError"], mapper_tree=mapper_tree) == RuntimeError

    # Test the case of an empty mapper

    mapper_tree = construct_status_slugs_mapper([Exception], fallback_exception_class=NotImplementedError)
    assert (
        get_closest_exception_class_for_status_slugs(["Exception"], mapper_tree=mapper_tree)
        == NotImplementedError  # Shadowns the "Exception" class which has an empty slug due to slugifier config
    )
    assert get_closest_exception_class_for_status_slugs(["OSError"], mapper_tree=mapper_tree) == NotImplementedError


def test_status_slugs_mapper_class():

    import builtins

    exception_classes = StatusSlugsMapper.gather_exception_subclasses(
        builtins, parent_classes=[LookupError, UnicodeDecodeError]
    )

    def qualified_name_extractor(exception_class):
        return "#%s#" % exception_class.__name__

    exception_slugifier = functools.partial(slugify_exception_class, qualified_name_extractor=qualified_name_extractor)

    mapper = StatusSlugsMapper(
        exception_classes, fallback_exception_class=RuntimeError, exception_slugifier=exception_slugifier
    )

    assert mapper.slugify_exception_class(FileNotFoundError) == ["#OSError#", "#FileNotFoundError#"]
    assert mapper.slugify_exception_class(UnicodeDecodeError) == [
        "#ValueError#",
        "#UnicodeError#",
        "#UnicodeDecodeError#",
    ]

    exc_class = mapper.get_closest_exception_class_for_status_slugs(
        slugs=["#ValueError#", "#UnicodeError#", "#UnicodeDecodeError#"]
    )
    assert exc_class == UnicodeDecodeError

    exc_class = mapper.get_closest_exception_class_for_status_slugs(
        slugs=["#ValueError#", "#UnicodeError#", "#UnicodeEncodeError#"]
    )
    assert exc_class == RuntimeError  # Ancestor classes were not included in "exception_classes"

    exc_class = mapper.get_closest_exception_class_for_status_slugs(slugs=["#ValueError#", "#UnicodeError#"])
    assert exc_class == RuntimeError  # Same thing

    exc_class = mapper.get_closest_exception_class_for_status_slugs(slugs=["#LookupError#", "#IndexError#"])
    assert exc_class == IndexError

    exc_class = mapper.get_closest_exception_class_for_status_slugs(slugs=["#LookupError#", "#SomeStuff#"])
    assert exc_class == LookupError

    exc_class = mapper.get_closest_exception_class_for_status_slugs(slugs=["#ABC#", "#DEF#"])
    assert exc_class == RuntimeError

    exc_class = mapper.get_closest_exception_class_for_status_slugs(slugs=[])
    assert exc_class == RuntimeError
