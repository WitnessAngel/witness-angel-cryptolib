import sys

from wacryptolib.error_handling import (
    _gather_exception_subclasses,
    _construct_status_slugs_mapper,
    _slugify_exception_class,
    _retrieve_exception_class_for_status_slugs,
    _fully_qualified_name,
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

    selected_classes = _gather_exception_subclasses(
        module=this_module, parent_classes=MyExc
    )
    assert set(selected_classes) == set(
        [MyExc, MyExcChild1, MyExcChild2, MyExcChild1GrandChild]
    ), selected_classes

    assert (
        _fully_qualified_name(LookupError) == "LookupError"
    )  # Builtins don't keep their module prefix
    assert _fully_qualified_name(MyExc) == "test_wacryptolib_error_handling.MyExc"

    mapper = _construct_status_slugs_mapper(
        selected_classes, fallback_exception_class=NotImplementedError
    )
    # from pprint import pprint ; pprint(mapper)
    assert mapper == {
        "": NotImplementedError,
        "test_wacryptolib_error_handling.MyExc": {
            "": MyExc,
            "test_wacryptolib_error_handling.MyExcChild1": {
                "": MyExcChild1,
                "test_wacryptolib_error_handling.MyExcChild1GrandChild": {
                    "": MyExcChild1GrandChild
                },
            },
            "test_wacryptolib_error_handling.MyExcChild2": {"": MyExcChild2},
        },
    }

    selected_classes = _gather_exception_subclasses(
        module=this_module, parent_classes=(EnvironmentError, RuntimeError)
    )
    assert set(selected_classes) == set([IOError, MyRuntimeError]), selected_classes

    selected_classes = _gather_exception_subclasses(
        module=this_module, parent_classes=(UnicodeError,)
    )
    assert set(selected_classes) == set(), selected_classes

    assert _slugify_exception_class(Exception) == [], _slugify_exception_class(
        Exception
    )
    assert _slugify_exception_class(MyExcChild1GrandChild) == [
        "test_wacryptolib_error_handling.MyExc",
        "test_wacryptolib_error_handling.MyExcChild1",
        "test_wacryptolib_error_handling.MyExcChild1GrandChild",
    ], _slugify_exception_class(MyExcChild1GrandChild)

    assert (
        _retrieve_exception_class_for_status_slugs((), mapper=mapper)
        == NotImplementedError
    )
    status_slug = (
        "test_wacryptolib_error_handling.MyExc",
        "test_wacryptolib_error_handling.MyExcChild1",
    )
    assert (
        _retrieve_exception_class_for_status_slugs(status_slug, mapper=mapper)
        == MyExcChild1
    )
    status_slug = (
        "test_wacryptolib_error_handling.MyExc",
        "test_wacryptolib_error_handling.XXXXXXXX",
    )
    assert (
        _retrieve_exception_class_for_status_slugs(status_slug, mapper=mapper)
        == NotImplementedError
    )
