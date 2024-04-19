import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.sql.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;


/**************************************************************
 *
 * Vulnerabilidades Implementadas:
 *
 * 1. Path Traversal Attack em readLog
 * 2. Hardcoded DEBUG User/Password em authenticate
 * 3. Password Hashing com MD5
 * 4. SQL Injection exploravel em authenticate e addUser (ref: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
 *
 *************************************************************/

class UserAuthentication {
    private Connection connection;

    UserAuthentication() {
        try {
            Class.forName("org.sqlite.JDBC");
            String dbFilePath = "config/database.db"; // arquivo do banco de dados
            File dbFile = new File(dbFilePath);

            if (!dbFile.exists()) {
                File parentDir = dbFile.getParentFile();
                if (!parentDir.exists()) {
                    parentDir.mkdirs();
                }
                dbFile.createNewFile();
                connection = DriverManager.getConnection("jdbc:sqlite:" + dbFilePath);
                createTable();
                addAdminUser();
            } else {
                connection = DriverManager.getConnection("jdbc:sqlite:" + dbFilePath);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createTable() throws SQLException {
        Statement statement = connection.createStatement();
        statement.executeUpdate("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, is_admin INTEGER)");
    }

    public boolean authenticate(String username, String password) {
        try {
            // Hardcoded debug user
            if (username.equals("debug") && password.equals("debug")) {
                System.out.println("Bypass authentication for 'debug' user.");
                return true; // Bypass authentication
            }

            // Vulneravel a SQL INJECTION:
            // PoC: USER INPUT : ' OR '1'='1'--

            String hashedPassword = hashPassword(password);
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashedPassword + "'";
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(query);
            return resultSet.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    private void addAdminUser() throws SQLException {
        String adminUsername = "admin";
        String adminPassword = "1234";
        String hashedPassword = hashPassword(adminPassword);

        String sqlQuery = "INSERT INTO users (username, password, is_admin) VALUES ('" + adminUsername + "', '" + hashedPassword + "', 1)";

        Statement statement = connection.createStatement();
        statement.executeUpdate(sqlQuery);
    }

    public boolean isAdminUser(String username) {
        try {
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND is_admin = 1";
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(query);
            return resultSet.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean addUser(String username, String password, boolean isAdmin) {
        try {
            // Impede o registo de users debug
            if (username.equals("debug")) {
                System.out.println("'debug' is a system user. cannot register.");
                return false;
            }

            int isAdminInt = isAdmin ? 1 : 0;
            String hashedPassword = hashPassword(password); // HASH em MD5
            String query = "INSERT INTO users (username, password, is_admin) VALUES ('" + username + "', '" + hashedPassword + "', " + isAdminInt + ")";
            Statement statement = connection.createStatement();
            statement.executeUpdate(query);
            return true;
        } catch (SQLException e) {
            // Verifica se a exceção foi causada por uma violação de restrição de chave única
            if (e.getMessage().contains("UNIQUE constraint failed: users.username")) {
                System.out.println("Nope, not today ;)");
            } else {
                e.printStackTrace();
            }
            return false;
        }
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}


class Peer {
    int localPort;
    int remotePort;
    String remoteHost;
    boolean connected;
    BufferedWriter logWriter;
    UserAuthentication auth;

    private static final String LOCK_FILE_PATH = "config/database.lock";
    private ReentrantReadWriteLock dbLock = new ReentrantReadWriteLock();


    Peer(String remoteHost, int localPort, int remotePort) {
        this.remoteHost = remoteHost;
        this.localPort = localPort;
        this.remotePort = remotePort;
        this.connected = false;
        acquireLock(false); // Para adquirir a trava para leitura

        // Obtém o diretório atual do users
        String currentDir = System.getProperty("user.dir");

        // Cria a pasta "logs" no diretório atual, se ela não existir
        File logsDir = new File(currentDir + File.separator + "logs");
        if (!logsDir.exists()) {
            logsDir.mkdirs();
        }

        try {
            // Cria o BufferedWriter para escrever no arquivo de log
            String timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
            String logFileName = currentDir + File.separator + "logs" + File.separator + remoteHost + "_" + timeStamp + ".log";
            File logFile = new File(logFileName);
            logFile.createNewFile();
            logWriter = new BufferedWriter(new FileWriter(logFile));
        } catch (IOException e) {
            e.printStackTrace();
        }

        auth = new UserAuthentication();
    }

    private void acquireLock(boolean forWrite) {
        while (true) {
            try {
                File lockFile = new File(LOCK_FILE_PATH);
                File lockDir = lockFile.getParentFile();
                if (!lockDir.exists()) {
                    lockDir.mkdirs();
                }
                if (!lockFile.exists()) {
                    lockFile.createNewFile();
                }
                RandomAccessFile randomAccessFile = new RandomAccessFile(lockFile, "rw");
                FileChannel channel = randomAccessFile.getChannel();

                FileLock lock = null;
                if (forWrite) {
                    lock = channel.tryLock();
                } else {
                    lock = channel.lock(0, Long.MAX_VALUE, true);
                }

                if (lock == null) {
                    System.err.println("Another instance is already registering a user in the database. Retrying...");
                    Thread.sleep(1000); // retry 1000 ms
                } else {
                    break;
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }
    }



    public void banner() {
        System.out.println("******************************************************");
        System.out.println("*                                                    *");
        System.out.println("*                Welcome to ChatP2P                  *");
        System.out.println("*          Totally a secure P2P application (;       *");
        System.out.println("*                                                    *");
        System.out.println("******************************************************");
        System.out.println("* If you need help just type: !help                  *");
        System.out.println("******************************************************");
    }


    public void printHelp() {
        System.out.println("------------------------------------------------------------");
        System.out.println("Available commands:\n");
        System.out.println("!help - Display this help message");
        System.out.println("!listlogs - List all available log files");
        System.out.println("!readlogs <logFileName> - Read the contents of a log file");
        System.out.println("!panic - Send a panic message to close the connection");
        System.out.println("------------------------------------------------------------");
    }

    public void registerUser() throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        // Adquire a trava de escrita antes de registrar um usuário
        Lock writeLock = dbLock.writeLock();

        // Tenta adquirir a trava
        try {
            writeLock.lock();

            while (true) {
                System.out.println("Enter a username: ");
                String username = reader.readLine();

                System.out.println("Enter a password: ");
                String password = reader.readLine();

                boolean isAdmin = false;

                if (auth.addUser(username, password, isAdmin)) {
                    System.out.println("User registered successfully.");
                    break; // Sai do loop se o usuário for registrado com sucesso
                } else {
                    System.out.println("Username already exists. Please choose a different username.");
                }
            }
        } finally {
            // Libera a trava de escrita após concluir o registro do usuário
            writeLock.unlock();
        }
    }



    public void startPeer(String username) throws InterruptedException {
        Sender s = new Sender(username);
        Receiver r = new Receiver(localPort, 5000); // timeout em 5000 ms (5 secs)

        int retryC = 0;
        while (retryC < 3) {
            try {
                s.start();
                r.start();

                s.join();
                r.join();
                break;
            } catch (Exception e) {
                System.out.println("retry " + e);
                retryC++;
            }
        }
    }

    class Sender extends Thread {
        String username;

        Sender(String username) {
            this.username = username;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                Socket s = null;
                DataOutputStream broadcast = null;
                boolean connected = false;

                while (!connected) {
                    try {
                        s = new Socket(remoteHost, remotePort);
                        broadcast = new DataOutputStream(s.getOutputStream());
                        connected = true;
                    } catch (ConnectException e) {
                        System.out.println("[-] Connection refused: Unable to connect to the remote host. Retrying...");
                        Thread.sleep(1000); // Espera 1 sec antes de tentar novamente
                    }
                }

                while (true) {
                    System.out.print("> ");
                    String message = in.readLine();

                    if (message.isEmpty()) {
                        // ignora empty spaces
                    } else if (message.equalsIgnoreCase("!panic")) {

                        if (username.equals("debug") || auth.isAdminUser(username)) {
                            System.out.println("Sending panic message...");
                            broadcast.writeUTF(message);
                            s.close();
                            System.exit(1);
                            break;
                        } else {
                            System.out.println("Nope. Only admin users can send a panic message.");
                        }

                    } else if (message.equalsIgnoreCase("!listlogs")) {
                        listLogs();
                    } else if (message.startsWith("!readlog")) {

                        String[] parts = message.split(" ");
                        if (parts.length == 2) {
                            readLog(parts[1]);
                        } else {
                            System.out.println("Usage: !readlog <logFileName>");
                        }
                    } else if (message.equalsIgnoreCase("!help")) {
                        printHelp();
                    } else {
                        // Dá broadcast do user + mensagem
                        broadcast.writeUTF(username + ": " + message);
                        System.out.println("Message sent");

                        // Guarda a mensagem enviada no arquivo de log
                        logWriter.write("Sent: " + message + "\n");
                        logWriter.flush();
                    }
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }
    }


    class Receiver extends Thread {
        ServerSocket ss;
        BufferedWriter logWriter;
        boolean connected;

        Receiver(int port, int timeout) {
            try {
                ss = new ServerSocket(port);
                connected = false;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void run() {
            while (true) { // Loop até infinito e mais além para continuar a aceitar conexões
                try {
                    Socket s = ss.accept();
                    System.out.println("[+] Client connected");
                    banner(); // Mostra o banner

                    DataInputStream broadcast = new DataInputStream(s.getInputStream());
                    connected = true;

                    while (true) {
                        String message = broadcast.readUTF();
                        System.out.println(message);

                        // Guarda a mensagem recebida no ficheiro de log
                        if (logWriter != null) {
                            logWriter.write("Received: " + message + "\n");
                            logWriter.flush();
                        }
                    }

                } catch (SocketTimeoutException e) {
                    // Não faz nada se ocorrer um timeout
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void listLogs() {
        File logsDir = new File("logs");
        if (logsDir.exists() && logsDir.isDirectory()) {
            File[] logFiles = logsDir.listFiles();
            System.out.println("Available log files:");
            for (File file : logFiles) {
                if (file.isFile()) {
                    System.out.println(file.getName());
                }
            }
        } else {
            System.out.println("No log files found.");
        }
    }

    // Lê o os logs do cliente
    // Vulnerável a Path traversal Attack
    // PoC: !readlogs ../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd
    public void readLog(String logFileName) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("logs" + File.separator + logFileName));
            String line;
            System.out.println("Contents of " + logFileName + ":");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (IOException e) {
            System.out.println("Error reading log file: " + e.getMessage());
        }
    }
}

public class chatP2P {
    public static void main(String[] args) throws InterruptedException {
        if (args.length != 3) {
            System.out.println("Usage: <host> <localPort> <remotePort>");
            return;
        }

        String remoteHost = args[0];
        int localPort = Integer.parseInt(args[1]);
        int remotePort = Integer.parseInt(args[2]);

        Peer p = new Peer(remoteHost, localPort, remotePort);

        try {
            System.out.println("[+] New peer created.");

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("***************************************************");
            System.out.println("Do you want to register as a new user? (yes/no): ");
            System.out.println("***************************************************");
            String registerChoice = reader.readLine();

            if (registerChoice.equalsIgnoreCase("yes")) {
                p.registerUser();
            }
            System.out.println("\n\n**************************************");
            System.out.println("*              Login                 *");
            System.out.println("**************************************");
            System.out.println("Enter your username: ");
            String username = reader.readLine();
            System.out.println("Enter your password: ");
            String password = reader.readLine();

            if (!p.auth.authenticate(username, password)) {
                System.out.println("Invalid username or password.");
                return;
            }

            System.out.println("[!] Waiting for a remote peer connection... [!]");
            p.startPeer(username);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}