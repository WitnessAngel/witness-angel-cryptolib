import logging

logger = logging.getLogger(__name__)


def gather_exception_subclasses(module, parent_classes: list):
    """
    Browse the module's variables, and return all found exception classes
    which are subclasses of `parent_classes`(including these, if found in module).

    :param module: python module object
    :param parent_classes: list of exception classes
    :return: list of exception subclasses
    """
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


DEFAULT_EXCLUDED_CLASSES = (object, BaseException, Exception)


def slugify_exception_class(
    exception_class,
    excluded_classes=DEFAULT_EXCLUDED_CLASSES,
    qualified_name_extractor=_fully_qualified_name,
):
    """
    Turn an exception class into a list of slugs which identifies it uniquely,
    from ancestor to descendant.

    :param exception_class: exception class to slugify
    :param excluded_classes: parents classes so generic that they needn't be included in slugs
    :param qualified_name_extractor: callable which turns an exception class into its qualified name
    :return: list of strings
    """
    # TODO change casing? Inspect exception_class.slug_name?
    return [
        qualified_name_extractor(ancestor)
        for ancestor in reversed(exception_class.__mro__)
        if ancestor not in excluded_classes
    ]


def construct_status_slugs_mapper(
    exception_classes, fallback_exception_class, slugifier=slugify_exception_class
):
    """
    Construct and return a tree where branches are qualified slugs, and each leaf is an exception
    class corresponding to the path leading to it.

    The fallback exception class is stored at the root of the tree under the "" key.
    """

    mapper = {"": fallback_exception_class} # Special value at root

    for exception_class in exception_classes:
        slugs = slugifier(exception_class)
        assert slugs, slugs
        current = mapper
        for slug in slugs:
            current = current.setdefault(slug, {})
        current[""] = exception_class

    return mapper


def retrieve_closest_exception_class_for_status_slugs(slugs, mapper):
    """
    Return the exception class targeted by the provided status slugs,
    or the closest ancestor class if the exact exception class is not in the mapper.

    If `slugs` is empty, or if no ancestor is found, the fallback exception of the mapper is returned instead.

    :param slugs: qualified status slugs
    :param mapper: mapper tree constructed from selected exceptions
    :return: exception class object
    """
    current = mapper
    for slug in slugs:
        fallback_exception_class = current[""]
        current = current.get(slug)
        if current is None:
            return fallback_exception_class
    return current[""]
