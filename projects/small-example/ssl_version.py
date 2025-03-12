import websockify

class WebSocketProxy(websockify.WebSocketProxy):
    def __init__(self, *args, **kwargs):
        self.security_proxy = kwargs.pop('security_proxy', None)
        ssl_min_version = kwargs.pop('ssl_minimum_version', None)
        if ssl_min_version and ssl_min_version != 'default':
            kwargs['ssl_options'] = websockify.websocketproxy. \
                select_ssl_version('tlsv1_3')
        pass
