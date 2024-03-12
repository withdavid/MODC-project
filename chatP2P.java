import java.io.*;
import java.net.*;
import java.util.Timer;
import java.util.TimerTask;

class Peer {

    int localPort;
    int remotePort;
    String remoteHost;
    boolean connected;

    Peer (String remoteHost, int localPort, int remotePort) {
        this.remoteHost = remoteHost;
        this.localPort = localPort;
        this.remotePort = remotePort;
        this.connected = false;
    }

    class Sender extends Thread {

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("Sender created.");

                Socket s = new Socket(remoteHost, remotePort);
                DataOutputStream broadcast = new DataOutputStream(s.getOutputStream());

                while (true) {
                    System.out.print("> ");
                    String message = in.readLine();

                    if (message.isEmpty()) {
                        // ignora empty spaces
                    }
                    else if (message.equalsIgnoreCase("!panic")) {

                        // Panic Message
                        // Força o peer a fechar o socket

                        System.out.println("Sending panic message...");
                        broadcast.writeUTF(message);
                        s.close();
                        break;

                    } else {
                        broadcast.writeUTF(message);
                        System.out.println("Message sent");
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    class Receiver extends Thread {

        ServerSocket ss;

        Receiver(int port) {
            try {
                ss = new ServerSocket(port);
                System.out.println("Receiver created.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void run() {
            try {
                Socket s = ss.accept();
                System.out.println("Client connected");

                DataInputStream broadcast = new DataInputStream(s.getInputStream());
                connected = true;

                while (true) {
                    String message = broadcast.readUTF();
                    System.out.println("Peer: " + message);
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void newPeer() throws InterruptedException {
        Sender s = new Sender();
        Receiver r = new Receiver(localPort);

        s.start();
        r.start();

        s.join();
        r.join();
    }

    public static void main(String[] args) throws InterruptedException {
        if (args.length != 3) {
            System.out.println("Usage: Peer <host> <localPort> <remotePort>");
            return;
        }

        String remoteHost = args[0];
        int localPort = Integer.parseInt(args[1]);
        int remotePort = Integer.parseInt(args[2]);

        Peer p = new Peer(remoteHost, localPort, remotePort);
        try {
            System.out.println("New peer created.");
            p.newPeer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void waitForConnection() {
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                // Se o peer não se conectar até 1 minuto, o programa vai de vela
                if (!connected) {
                    System.out.println("Connection failed: Peer did not connect within 1 minute.");
                    System.exit(1);
                }
            }
        }, 60000); // 1 min
    }
}
