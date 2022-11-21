from rest_framework import pagination


class StandardResultsSetPagination(pagination.PageNumberPagination):
    page_size = 6
    page_query_param = "page"
    page_size_query_param = "page_size"
    max_page_size = 1000


class LargeResultsSetPagination(pagination.PageNumberPagination):
    page_size = 100
    page_query_param = "page"
    page_size_query_param = "page_size"
    max_page_size = 1000
