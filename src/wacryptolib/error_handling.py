import logging

logger = logging.getLogger(__name__)


def gather_exception_subclasses(module, parent_classes: list):
    """
    Browse the module's variables, and return all found exception classes
    which are subclasses of `parent_classes` (including these, if found in module).

    :param module: python module object
    :param parent_classes: list of exception classes (or single exception class)
    :return: list of exception subclasses
    """
    parent_classes = tuple(parent_classes) if isinstance(parent_classes, list) else parent_classes
    selected_classes = []
    for (key, value) in vars(module).items():
        if isinstance(value, type):
            # print ("checking", key, value, issubclass(value, parent_classes), parent_classes)
            if issubclass(value, parent_classes):  # Includes parent classes themselves
                # print("DONE")
                selected_classes.append(value)
    return selected_classes


def _fully_qualified_name(o):
    """Return the fully qualified dotted name of an object, as a string."""
    module = o.__module__
    if module is None or module == str.__module__:
        return o.__name__  # Avoid reporting __builtin__
    else:
        return module + "." + o.__name__


#: These ancestor classes are too generic to be included in status slugs
DEFAULT_EXCLUDED_EXCEPTION_CLASSES = (object, BaseException, Exception)


def slugify_exception_class(
    exception_class, excluded_classes=DEFAULT_EXCLUDED_EXCEPTION_CLASSES, qualified_name_extractor=_fully_qualified_name
):
    """
    Turn an exception class into a list of slugs which identifies it uniquely,
    from ancestor to descendant.

    :param exception_class: exception class to slugify
    :param excluded_classes: list of parents classes so generic that they needn't be included in slugs
    :param qualified_name_extractor: callable which turns an exception class into its qualified name
    :return: list of strings
    """
    # TODO change casing? Inspect exception_class.slug_name?
    assert isinstance(exception_class, type), exception_class  # Must be a CLASS, not an instance!
    slugs = [
        qualified_name_extractor(ancestor)
        for ancestor in reversed(exception_class.__mro__)
        if ancestor not in excluded_classes
    ]
    return slugs


def construct_status_slugs_mapper(
    exception_classes, fallback_exception_class, exception_slugifier=slugify_exception_class
):
    """
    Construct and return a tree where branches are qualified slugs, and each leaf is an exception
    class corresponding to the path leading to it.

    Intermediate branches can carry an (ancestor) exception class too, but only if this one is explicitely
    included in `exception_classes`.

    The fallback exception class is stored at the root of the tree under the "" key.
    """

    mapper_tree = {"": fallback_exception_class}  # Special value at root

    for exception_class in exception_classes:
        slugs = exception_slugifier(exception_class)
        if not slugs:
            continue  # E.g. for BaseException and the likes, shadowed by fallback_exception_class
        current = mapper_tree
        for slug in slugs:
            current = current.setdefault(slug, {})  # No auto-creation of entries for ancestors
        current[""] = exception_class

    return mapper_tree


def get_closest_exception_class_for_status_slugs(slugs, mapper_tree):
    """
    Return the exception class targeted by the provided status slugs,
    or the closest ancestor class if the exact exception class is not in the mapper.

    If `slugs` is empty, or if no ancestor is found, the fallback exception of the mapper is returned instead.

    :param slugs: qualified status slugs
    :param mapper: mapper tree constructed from selected exceptions
    :return: exception class object
    """
    current = mapper_tree
    fallback_exception_class = mapper_tree[""]  # Ultimate root fallback
    for slug in slugs:
        current = current.get(slug)
        if current is None:
            return fallback_exception_class
        else:
            fallback_exception_class = current.get("", fallback_exception_class)
    return current.get("", fallback_exception_class)


class StatusSlugsMapper:
    """
    High-level wrapper for converting exceptions from/to status slugs.
    """

    def __init__(self, exception_classes, fallback_exception_class, exception_slugifier=slugify_exception_class):
        self._slugify_exception_class = exception_slugifier
        self._mapper_tree = construct_status_slugs_mapper(
            exception_classes=exception_classes,
            fallback_exception_class=fallback_exception_class,
            exception_slugifier=exception_slugifier,
        )

    def slugify_exception_class(self, exception_class, *args, **kwargs):
        """Use the exception slugifier provided in `__init__()` to turn an exception class into a qualified name."""
        return self._slugify_exception_class(exception_class, *args, **kwargs)

    def get_closest_exception_class_for_status_slugs(self, slugs):
        """Return the closest exception class targeted by the provided status slugs,
        with a fallback class if no matching ancestor is found at all."""
        return get_closest_exception_class_for_status_slugs(slugs, mapper_tree=self._mapper_tree)

    gather_exception_subclasses = staticmethod(gather_exception_subclasses)
