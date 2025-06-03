class Controller():
    def create(self):
        pass

class Extension():
    alias = "encryption"
    def get_resources(self):
        return extensions.ResourceExtension(Extension.alias, Controller(), parent=dict(member_name='type', collection_name='types'))
