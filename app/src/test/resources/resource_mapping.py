self.resources['types'] = types.create_resource()
mapper.resource("type", "types", controller=self.resources['types'], member={'action': 'POST'})
