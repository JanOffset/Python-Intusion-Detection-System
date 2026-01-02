import pyshark as psh
import netifaces as nif
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

class SimpleIDS:
    def __init__(self, 
                 connection_threshold=30,  
                 contamination=0.1):       
        """
        IDS with basic ML
        
        Args:
            connection_threshold (int): Threshold 
            contamination (float): Fraction 
        """
        
        self.suspicious_log_file = 'suspicious_ips.txt'
        self.alert_log_file = "alert.txt"
        
        
        try:
            open(self.suspicious_log_file, "w").close()
            open(self.alert_log_file, "w").close()
            print(f"Log files created: {self.suspicious_log_file}, {self.alert_log_file}")
        except Exception as e:
            print(f"Error creating log files: {e}")
            print("Make sure you have write permissions in the current directory")
        
        
        self.connection_threshold = connection_threshold
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        self.ip_connections = {}
        self.features_list = []
        self.min_samples_for_ml = 100  
        self.startup_time = time.time()
        
        print(" IDS initialized - waiting 10 seconds ...")

    def extract_features(self, src_ip, dst_port, packet_length):
        """Extract features from packet for anomaly detection"""
        current_time = time.time()
        
        
        if src_ip not in self.ip_connections:
            self.ip_connections[src_ip] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'total_connections': 0,
                'unique_ports': set(),
                'packet_sizes': [],
                'connection_times': []
            }
        
        ip_data = self.ip_connections[src_ip]
        
        ip_data['last_seen'] = current_time
        ip_data['total_connections'] += 1
        if dst_port:
            ip_data['unique_ports'].add(dst_port)
        ip_data['packet_sizes'].append(int(packet_length))
        ip_data['connection_times'].append(current_time)
        
       
        time_window = 5  
        recent_time = current_time - time_window
        
       
        recent_connections = sum(1 for t in ip_data['connection_times'] 
                                if t > recent_time)
        
        connection_rate = recent_connections / time_window
        
        if len(ip_data['connection_times']) > 100:
            ip_data['connection_times'] = ip_data['connection_times'][-100:]
       
        if len(ip_data['packet_sizes']) > 100:
            ip_data['packet_sizes'] = ip_data['packet_sizes'][-100:]
        
        avg_packet_size = sum(ip_data['packet_sizes']) / len(ip_data['packet_sizes'])
        
        features = [
            ip_data['total_connections'],
            len(ip_data['unique_ports']),
            connection_rate,
            avg_packet_size,
            current_time - ip_data['first_seen']  
        ]
        
        return features, connection_rate

    def analyze_packet(self, packet):
        """Analyze packet for intrusions"""
        try:
            
            if time.time() - self.startup_time < 10:
                return
                
           
            if 'IP' not in packet:
                return
                
          
            ip_layer = packet.ip
            tcp_layer = packet.tcp if 'TCP' in packet else None
            src_ip = ip_layer.src
            dst_port = int(tcp_layer.dstport) if tcp_layer else None
            packet_length = int(packet.length)
            
            if src_ip in ['127.0.0.1', '0.0.0.0'] or src_ip.startswith('169.254'):
                return
            
            
            features, connection_rate = self.extract_features(src_ip, dst_port, packet_length)
            self.features_list.append(features)
            
            is_suspicious = False
            detection_type = []
            
            if len(self.features_list) < 50:
                return
            
            if connection_rate > 10:
                is_suspicious = True
                detection_type.append("HIGH_RATE")
            
            if src_ip in self.ip_connections and self.ip_connections[src_ip]['total_connections'] > self.connection_threshold:
                is_suspicious = True
                detection_type.append("TOTAL_CONN")
            
            if src_ip in self.ip_connections and len(self.ip_connections[src_ip]['unique_ports']) > 10:
                is_suspicious = True
                detection_type.append("PORT_SCAN")
            
            if len(self.features_list) >= self.min_samples_for_ml:
                if len(self.features_list) % 100 == 0:
                    self._train_model()
                
                feature_array = np.array([features])
                prediction = self.model.predict(feature_array)
                
                if prediction[0] == -1: 
                    is_suspicious = True
                    detection_type.append("ML")

            if is_suspicious:
                self._log_suspicious(src_ip, ", ".join(detection_type))
    
            if tcp_layer:
                flags = str(tcp_layer.flags)
                
                if len(self.features_list) % 100 == 0:
                    print(f"DEBUG - TCP flags format: {flags}")
                
                if ("0x002" in flags or "0x02" in flags or 
                    "SYN" in flags or "02" in flags or
                    "2" == flags):
                    alert_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: SYN packet detected from {src_ip}\n"
                    print(alert_message.strip())
                    try:
                        with open(self.alert_log_file, "a") as f:
                            f.write(alert_message)
                        print(f"SYN alert written to {self.alert_log_file}")
                    except Exception as e:
                        print(f"Error writing to alert log: {e}")
                        
        except Exception as e:
            print(f"Error analyzing packet: {e}")

    def _train_model(self):
        """Train the ML model with collected data"""
        if len(self.features_list) < self.min_samples_for_ml:
            return
            
        print(f"Training ML model with {len(self.features_list)} samples")
        
        X = np.array(self.features_list)
        
        if len(X) > 10000:
            X = X[-10000:]
        
        self.model.fit(X)
        print("ML model training complete")

    def _log_suspicious(self, ip, detection_type):
        """Log suspicious IP activity"""
        ip_data = self.ip_connections[ip]
        
        message = (f"\n[SUSPICIOUS IP DETECTED - {detection_type}] {ip}\n"
                  f"Total Connections: {ip_data['total_connections']}\n"
                  f"Unique Ports: {len(ip_data['unique_ports'])}")
        
        print(message)
        
        try:
            with open(self.suspicious_log_file, "a") as f:
                f.write(f"{datetime.now().isoformat()} - {ip} - {detection_type}\n")
            print(f"Logged to {self.suspicious_log_file}")
        except Exception as e:
            print(f"Error writing to log file: {e}")
        
            try:
                with open(self.suspicious_log_file, "w") as f:
                    f.write(f"{datetime.now().isoformat()} - {ip} - {detection_type}\n")
                print(f"Created and wrote to {self.suspicious_log_file}")
            except Exception as e2:
                print(f"Failed to create log file: {e2}")


def start_monitoring():
    """Start the IDS monitoring"""
    gateways = nif.gateways()
    if 'default' in gateways and nif.AF_INET in gateways['default']:
        intF = gateways['default'][nif.AF_INET][1]
        print("Interface from netifaces:", intF)
    else:
        print("No default gateway found!")
        exit(1)

    expected_prefix = r"\Device\NPF_"
    if not intF.startswith(expected_prefix):
        intF = expected_prefix + intF
    print("Windows interface format:", intF)
    
    ids = SimpleIDS(connection_threshold=30)
    
    try:
        print(f"Starting packet capture on {intF}")
        print("Press Ctrl+C to stop the IDS")
        
        capture = psh.LiveCapture(interface=intF)
        
        packet_count = 0
        for packet in capture.sniff_continuously():
            try:
                ids.analyze_packet(packet)
                packet_count += 1
                
                if packet_count % 100 == 0:
                    print(f"Processed {packet_count} packets")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                
    except KeyboardInterrupt:
        print("\nIDS monitoring stopped by user")
    except Exception as e:
        print(f"Error starting capture: {e}")


if __name__ == "__main__":
    print(" Intrusion Detection System")
    print("Starting monitoring on default interface...")
    start_monitoring()
