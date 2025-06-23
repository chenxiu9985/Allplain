from abc import ABC, abstractmethod

class ScanTask(ABC):
    def __init__(self, targets):
        self.targets = targets

    @abstractmethod
    def run(self):
        raise NotImplementedError("Subclasses must implement the run() method")

