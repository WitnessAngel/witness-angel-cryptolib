def _gather_exception_subclasses(module, parent_classes):
    selected_classes = []
    for (key, value) in vars(module).items():
        if isinstance(value, type):
            # print ("checking", key, value, issubclass(value, parent_classes), parent_classes)
            if issubclass(value, parent_classes):  # Includes parent classes themselves
                # print("DONE")
                selected_classes.append(value)
    return selected_classes


def _fully_qualified_name(o):
    # print (repr(o))
    module = o.__module__
    if module is None or module == str.__module__:
        return o.__name__  # Avoid reporting __builtin__
    else:
        return module + "." + o.__name__


DEFAULT_EXCLUDED_CLASSES = (object, BaseException, Exception)


def _slugify_exception_class(
    exception_class,
    excluded_classes=DEFAULT_EXCLUDED_CLASSES,
    qualified_name_extractor=_fully_qualified_name,
):
    # TODO change casing? Inspect exception_class.slug_name?
    return [
        qualified_name_extractor(ancestor)
        for ancestor in reversed(exception_class.__mro__)
        if ancestor not in excluded_classes
    ]


def _construct_status_slugs_mapper(
    exception_classes, fallback_exception_class, slugifier=_slugify_exception_class
):
    mapper = {"": fallback_exception_class}

    for exception_class in exception_classes:
        slugs = slugifier(exception_class)
        current = mapper
        for slug in slugs:
            current = current.setdefault(slug, {})
        current[""] = exception_class

    return mapper


def _retrieve_exception_class_for_status_slugs(slugs, mapper):
    fallback_exception_class = mapper[""]  # Special value
    current = mapper
    for slug in slugs:
        current = current.get(slug)
        if current is None:
            return fallback_exception_class
    return current[""]  # Also works if slugs is empty
