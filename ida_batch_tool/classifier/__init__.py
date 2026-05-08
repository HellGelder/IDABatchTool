"""Классификатор импортированных модулей с детальными описаниями."""
from .platform_classifier import classify_module, get_platform_classifier
from .categories import get_module_category_and_description

__all__ = ['classify_module', 'get_module_category_and_description', 'get_platform_classifier']