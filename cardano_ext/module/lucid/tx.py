from core.mod import C
from lucid import Lucid


class Tx:
    def __init__(self, lucid: Lucid):
        self.txBuilder = C.TransactionBuilder.new(lucid.txBuilderConfig)
        self.tasks = []
        self.lucid = lucid

