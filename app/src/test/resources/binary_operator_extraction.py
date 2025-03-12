class Controller(base):
    def create(self, volume_type):
        return self._create("/types/%s/encryption" % volume_type)