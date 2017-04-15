package intrusiondetector;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;  
import java.util.Hashtable;
import java.util.Map;  
  
import org.jnetpcap.Pcap;   
import org.jnetpcap.packet.JPacket;  
import org.jnetpcap.packet.JPacketHandler;  
import org.jnetpcap.protocol.tcpip.Tcp;   
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.protocol.network.Ip4;

/* Aaron McCarthy
 * 
 */

public class ids {

    public static void main(String[] args) {
     final String fileName = "lbl-internal.20041004-1305.port002.dump.pcap"; //TODO make this command line
        final StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(fileName, errbuf);
        if (pcap == null) {  
            System.err.println(errbuf); 
            return;  
        }
        Map<String, Integer> synTable = new HashMap<String, Integer>();           //tables to store num synpkts and ackpkts sent by each ip
        Hashtable<String, Integer> ackTable = new Hashtable<String, Integer>();
        
        pcap.loop(-1, new JPacketHandler<StringBuilder>() {                 //loop thu all the pkts
            final Tcp tcp = new Tcp();  
            final Ip4 ip = new Ip4();
  
            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
                
                if (packet.hasHeader(tcp) && tcp.flags() == 0x002 && packet.hasHeader(ip)) {        try {
                    //if syn pkt
                    
                    InetAddress addr = InetAddress.getByAddress(ip.source());
                    if(synTable.containsKey(addr.getHostAddress())){             //if ip in table iterate num synpkts
                        
                        
                        synTable.put(addr.getHostAddress(), synTable.get(addr.getHostAddress()) +1);
                        //System.out.println(ip.sourceToInt());
                    }
                    else{                                                   //if ip not in table add and set val to 1
                        synTable.put(addr.getHostAddress(), 1);
                        //System.out.println(ip.sourceToInt());
                    }} catch (UnknownHostException ex) {
                        Logger.getLogger(scannerfinder.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
                }
                else if (packet.hasHeader(tcp) && tcp.flags() == 0x012 && packet.hasHeader(ip)) {        try {
                    //if synack pkt
                    InetAddress addr = InetAddress.getByAddress(ip.destination());
                    if(ackTable.containsKey(addr.getHostAddress())){             //if ip in table iterate num ackpkts 
                        ackTable.put(addr.getHostAddress(), ackTable.get(addr.getHostAddress()) +1);
                        //System.out.println(ip.sourceToInt());
                    }
                    else{                                                   //if ip not in table add and set val to 1
                        ackTable.put(addr.getHostAddress(), 1);
                        //System.out.println(ip.sourceToInt());
                    }
                    } catch (UnknownHostException ex) {
                        Logger.getLogger(scannerfinder.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
                }
   
            }  
  
        }, errbuf); 
        
    for (String key : synTable.keySet()) {
        if(!ackTable.containsKey(key) || synTable.get(key) >= 3 * ackTable.get(key) ){
            System.out.println(key);
        }
    }
  
        pcap.close();  
  
    
    }

}
                   