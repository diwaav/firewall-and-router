# copy of the firewall to play with

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
import time

log = core.getLogger()

def check(k, v):
  accept = { "20.1.1.10" : ["20.1.1.55"], 
                "20.1.1.55" : ["20.1.1.10", "20.1.1.11","20.1.1.30","20.1.1.31"],
                "20.1.1.11" : ["20.1.1.55"],
                "20.1.1.31" : ["20.1.1.55"]  }
  for key, value in accept.items():
    if key == k:
      # check inside the 
      for i in value:
        if i == v:
          return True;
  return False;

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    def drop():
      msg.data = packet_in
      self.connection.send(msg)
    def ok():
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = packet_in
      self.connection.send(msg)

    ip = packet.find('ipv4')
    icmp = packet.find('icmp')
    arp = packet.find('arp')
    tcp = packet.find('tcp')

    if (arp or icmp):
      ok()
      return;
    elif (tcp):
      if (check(str(msg.match.nw_src), str(msg.match.nw_dst))):
        ok()
        return;
    drop()
    return;

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
