

class MessageUpdate:

    # do not do anything. this should not occurr
    NO_ACTION = 'NO_ACTION'
    # can be used to just set the body to a value
    GET_BODY = 'GET_BODY'
    # add a parameter (url, body, cookie)
    ADD_PARAMETER = 'ADD_PARAMETER'
    # delete a parameter
    DEL_PARAMETER = 'DEL_PARAMETER'
    # update a parameter
    UPDATE_PARAMETER = 'UPDATE_PARAMETER'
    # build a complete http message (WARNING: this will overwrite the whole message, previous changes will be ignored!)
    BUILD_HTTP_MESSAGE = 'BUILD_HTTP_MESSAGE'
    # replace the full request or response
    REPLACE_REQUEST_RESPONSE = 'REPLACE_REQUEST_RESPONSE'
    # replace the request body
    REPLACE_REQUEST_BODY = 'REPLACE_REQUEST_BODY'
    # replace the response body
    REPLACE_RESPONSE_BODY = 'REPLACE_RESPONSE_BODY'
    # update the request headers
    UPDATE_REQUEST_HEADERS = 'UPDATE_REQUEST_HEADERS'
    # base64 decode the value given in body
    BASE64_DECODE_BODY = 'BASE64_DECODE_BODY'

    # proxylistener only
    ACTION_DO_INTERCEPT = 'ACTION_DO_INTERCEPT'
    ACTION_DO_INTERCEPT_AND_REHOOK = 'ACTION_DO_INTERCEPT_AND_REHOOK'
    ACTION_DONT_INTERCEPT = 'ACTION_DONT_INTERCEPT'
    ACTION_DONT_INTERCEPT_AND_REHOOK = 'ACTION_DONT_INTERCEPT_AND_REHOOK'
    ACTION_DROP = 'ACTION_DROP'
    ACTION_FOLLOW_RULES = 'ACTION_FOLLOW_RULES'
    ACTION_FOLLOW_RULES_AND_REHOOK = 'ACTION_FOLLOW_RULES_AND_REHOOK'

    # parameter type url
    PARAM_URL = 0
    # parameter type body
    PARAM_BODY = 1
    # parameter type cookie
    PARAM_COOKIE = 2

    def __init__(self):
        self.action = self.NO_ACTION

        # message headers and body, only used for BUILD_HTTP_MESSAGE
        self.headers = []
        # base64 encoded request/response body, full request or full response, can also be a payload or similar
        # important: the base64 encoding is needed for the transport, so a base64 encoded value will
        # lead to double b64 encoding
        self.body = ''

        # parameter info, only used for ADD_PARAMETER, UPDATE_PARAMETER
        self.paramName = ''
        self.paramValue = ''
        self.paramType = self.PARAM_BODY

    def get_data(self):
        return self.__dict__
