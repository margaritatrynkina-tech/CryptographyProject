@property
def connection(self):
    if not self._conn:
        self.connect()
    return self._conn
