class ClassWithImplicitConstructor:
    def doStuff(self):
        return "Doing stuff in ClassWithImplicitConstructor"

class ClassWithExplicitConstructor:
    def __init__(self):
        self.name = "ClassWithExplicitConstructor"

    def doStuff(self):
        return "Doing stuff in {}".format(self.name)

def doStuff():
    return "Doing stuff in simple function"
