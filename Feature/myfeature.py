class MyFeature:
    """A basic Python feature module."""

    def __init__(self, name: str = "World"):
        self.name = name

    def greet(self) -> str:
        """Return a greeting message."""
        return f"Hello, {self.name}!"


def run_feature(name: str = "World") -> str:
    """Run the basic feature and return the greeting."""
    feature = MyFeature(name)
    return feature.greet()
