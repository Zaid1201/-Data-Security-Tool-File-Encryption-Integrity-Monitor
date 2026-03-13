// This program provides a Grpahical User Interface (GUI) that does the following:  
    // 1. Scans the local directory structure and list the files and folders along with metadata (e.g., size, timestamps, etc.).
    // 2. Encrypts and decrypts user-selected files and folders using the Advanced Encryption Standard (AES) algorithm.
    // 3. Provides password-based encryption for folders.
    // 4. Logs actions to a file.
// Computer Security (7531CYQR)
// Coursework 2 - Data Security Tool (Part 1)
// November 2025
// Zaid Daghash

import java.awt.*;
import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeSelectionModel;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.List;
import java.text.SimpleDateFormat;
import java.security.MessageDigest;


public class EncryptionGUI extends JFrame {

    private final JTree fileTree;
    private final DefaultTreeModel treeModel;
    private final JTextArea metadataArea;
    private final JTextArea statusArea;
    private final JButton scanButton, encryptButton, decryptButton, viewLogsButton; // buttons that will be used in the GUI
    private static final Path LOG_FILE = Paths.get("filecrypt_log.txt"); // logs file which is saved in the same directory as the code file (EncryptionGUI.java)
    private static final byte[] FILE_MAGIC = new byte[]{'F','E','N','C'}; // 4 bytes used at the start of encrypted single files
    private static final int HASH_LEN = 32; // SHA-256 length
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); // Time format used in system status messages and metadata output
    private Path lastScannedDir = null; // Last scanned directory

    public EncryptionGUI() {
        
        super("EncryptionGUI");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1000, 700);
        setLayout(new BorderLayout());
        // setting up the area that shows the scanned directory (tree)
        treeModel = new DefaultTreeModel(new DefaultMutableTreeNode("No scan yet"));
        fileTree = new JTree(treeModel);
        fileTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        JScrollPane treeScroll = new JScrollPane(fileTree);
        treeScroll.setPreferredSize(new Dimension(420, 600));
        add(treeScroll, BorderLayout.WEST);
        // setting up the right-hand pane (metadata area)
        JPanel right = new JPanel(new BorderLayout());
        metadataArea = new JTextArea();
        metadataArea.setEditable(false);
        metadataArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        metadataArea.setBorder(BorderFactory.createTitledBorder("File / Folder Metadata"));
        JScrollPane metaScroll = new JScrollPane(metadataArea);
        metaScroll.setPreferredSize(new Dimension(540, 380));
        // layout of buttons
        JPanel buttons = new JPanel();
        scanButton = new JButton("Scan");
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        viewLogsButton = new JButton("View Logs");
        buttons.add(scanButton);
        buttons.add(encryptButton);
        buttons.add(decryptButton);
        buttons.add(viewLogsButton);
        // layout of system status area
        statusArea = new JTextArea(6, 40);
        statusArea.setEditable(false);
        JScrollPane statusScroll = new JScrollPane(statusArea);
        statusScroll.setBorder(BorderFactory.createTitledBorder("System Status / Output"));
        right.add(metaScroll, BorderLayout.CENTER);
        right.add(buttons, BorderLayout.NORTH);
        right.add(statusScroll, BorderLayout.SOUTH);
        add(right, BorderLayout.CENTER);
        scanButton.addActionListener(e -> selecting_scan());
        fileTree.addTreeSelectionListener(this::select_obj);
        encryptButton.addActionListener(e -> selecting_encrypt());
        decryptButton.addActionListener(e -> selecting_decrypt());
        viewLogsButton.addActionListener(e -> selecting_view_logs());
        append_status("Click 'Scan' to scan a directory.");
    }

    //Adding system status messages
    private void append_status(String s) {
        String time = sdf.format(new Date());
        SwingUtilities.invokeLater(() -> {
            statusArea.append("[" + time + "] " + s + "\n");
            statusArea.setCaretPosition(statusArea.getDocument().getLength());
        });
    }

    //What happens when the 'Scan' button is clicked (Directory scanning mechanism)
    private void selecting_scan() {
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int res = fc.showOpenDialog(this);
        if (res != JFileChooser.APPROVE_OPTION) {
            // cancelling the scan operation
            append_status("Scan cancelled.");
            return;
        }
        File f = fc.getSelectedFile();
        lastScannedDir = f.toPath();
        append_status("Scanning started: " + f.getAbsolutePath());

        // scanning in the background
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            protected Void doInBackground() {
                DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode(new FileNode(f));
                treeModel.setRoot(rootNode);
                display_scanned_directory(f.toPath(), rootNode);
                return null;
            }
            protected void done() {
                treeModel.reload();
                append_status("Scanning completed.");
            }
        };
        worker.execute();
    }

    //Showing the contents in the left pane of the GUI after scanning
    private void display_scanned_directory(Path path, DefaultMutableTreeNode node) {
        try (Stream<Path> s = Files.list(path).sorted(Comparator.comparing(p -> p.getFileName().toString().toLowerCase()))) {
            s.forEach(p -> {
                DefaultMutableTreeNode child = new DefaultMutableTreeNode(new FileNode(p.toFile()));
                node.add(child);
                if (Files.isDirectory(p)) {
                    display_scanned_directory(p, child);
                }
            });
        } catch (IOException e) {
            //error occuring when scanning a directory
            append_status("Error while scanning: " + e.getMessage());
        }
    }

    //Refreshing the content in the left pane (tree/scanned directory) after a certain action has been taken, to reflect new or deleted files/folders
    private void refresh() {
        if (lastScannedDir == null) {
            return;
        }
        append_status("Refreshing scanned directory...");
        SwingWorker<Void, Void> w = new SwingWorker<>() {
            protected Void doInBackground() {
                DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode(new FileNode(lastScannedDir.toFile()));
                treeModel.setRoot(rootNode);
                display_scanned_directory(lastScannedDir, rootNode);
                return null;
            }
            protected void done() {
                treeModel.reload();
                append_status("Directory refreshed.");
            }
        };
        w.execute();
    }

    //Showing the metadata in the right pane after selecting an object from the left pane (tree)
    private void select_obj(TreeSelectionEvent e) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) fileTree.getLastSelectedPathComponent();
        if (node == null) {
            return;
        }
        Object obj = node.getUserObject();
        if (!(obj instanceof FileNode)) {
            return;
        }
        FileNode fn = (FileNode) obj;
        File file = fn.file;
        if (file == null) {
            return;
        }
        try {
            BasicFileAttributes attrs = Files.readAttributes(file.toPath(), BasicFileAttributes.class);
            StringBuilder sb = new StringBuilder();
            sb.append("Path: ").append(file.getAbsolutePath()).append("\n");
            sb.append("Name: ").append(file.getName()).append("\n");
            sb.append("Type: ").append(file.isDirectory() ? "Directory" : "File").append("\n");
            sb.append("Size: ").append(file.isFile() ? readable_size(file.length()) : "-").append("\n");
            sb.append("Created: ").append(sdf.format(new Date(attrs.creationTime().toMillis()))).append("\n");
            sb.append("Last Modified: ").append(sdf.format(new Date(attrs.lastModifiedTime().toMillis()))).append("\n");
            sb.append("Readable: ").append(file.canRead()).append(", Writable: ").append(file.canWrite()).append("\n");
            metadataArea.setText(sb.toString());
        } catch (IOException ex) {
            //error processing and displaying metadata
            metadataArea.setText("Error reading metadata: " + ex.getMessage());
        }
    }

    //What happens when I press the 'Encrypt' button (Encryption mechanism)
    private void selecting_encrypt() {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) fileTree.getLastSelectedPathComponent();
        if (node == null) {
            // pressing the button without selecting a file/folder
            append_status("No file/folder selected to encrypt.");
            return;
        }
        
        FileNode fn = (FileNode) node.getUserObject();
        if (fn.file == null) {
            return;
        }

        if (fn.file.isDirectory()) {
            // folder-level encryption: ask the user for a password
            JPasswordField pf = new JPasswordField();
            int ok = JOptionPane.showConfirmDialog(this, pf, "Enter password for folder encryption", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (ok != JOptionPane.OK_OPTION) { append_status("Folder encryption canceled."); return; }
            char[] pwd = pf.getPassword();
            if (pwd.length == 0) { append_status("Folder encryption canceled (empty password)."); return; }

            // collect list of files in background, then encrypt
            SwingWorker<Void, String> w = new SwingWorker<>() {
                protected Void doInBackground() {
                    try {
                        List<Path> files = list_files(fn.file.toPath());
                        publish("Encrypting folder: " + fn.file.getAbsolutePath() + " (" + files.size() + " files)");
                        encrypt_folder(files, pwd, this::publish);
                        publish("Folder encryption completed: " + fn.file.getAbsolutePath());
                        write_log("ENCRYPT_FOLDER", fn.file.getAbsolutePath());
                    } catch (Exception ex) {
                        publish("Folder encryption failed: " + ex.getMessage());
                    } finally {
                        Arrays.fill(pwd, '\0');
                    }
                    return null;
                }
                protected void process(List<String> chunks) {
                    for (String msg : chunks) append_status(msg);
                }
                protected void done() { refresh(); }
            };
            w.execute();
        } else {
            // file-level: a fixed ky/password is used
            char[] pwd = "default-file-key".toCharArray(); //built-in password for single file encryption/decryption
            SwingWorker<Void, String> w = new SwingWorker<>() {
                protected Void doInBackground() {
                    Path in = fn.file.toPath();
                    Path out = in.getParent().resolve(in.getFileName().toString() + ".enc");
                    try {
                        publish("Encrypting file: " + in);
                        encrypt_file(in, out, pwd);
                        Files.deleteIfExists(in);
                        publish("File encrypted: " + out);
                        write_log("ENCRYPT_FILE", in.toString());
                    } catch (Exception ex) {
                        publish("File encryption error: " + ex.getMessage());
                    }
                    return null;
                }
                protected void process(List<String> chunks) { 
                    for (String m: chunks) {
                        append_status(m); 
                    }
                }
                protected void done() {
                    Arrays.fill(pwd, '\0'); 
                    refresh(); 
                }
            };
            w.execute();
        }
    }

    //What happens when I press the 'Decrypt' button (Decryption mechanism)
    private void selecting_decrypt() {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) fileTree.getLastSelectedPathComponent();
        if (node == null) {
            // pressing the button without selecting a file/folder
            append_status("No file/folder selected to decrypt.");
            return;
        }
        FileNode fn = (FileNode) node.getUserObject();
        if (fn.file == null) {
            return;
        }

        // if selected object is a directory (folder)
        if (fn.file.isDirectory()) {
            // folder-level encryption: ask the user for a password
            JPasswordField pf = new JPasswordField();
            int ok = JOptionPane.showConfirmDialog(this, pf, "Enter password for folder decryption", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE); // prompt for entering password
            if (ok != JOptionPane.OK_OPTION) { 
                append_status("Folder decryption canceled."); 
                return; 
            }
            char[] pwd = pf.getPassword();

            // if password field is left empty
            if (pwd.length == 0) { 
                append_status("Folder decryption canceled (empty password)."); 
                return; 
            }

            SwingWorker<Void, String> w = new SwingWorker<>() {
                protected Void doInBackground() {
                    try {
                        // collect only .enc files (stable snapshot)
                        List<Path> allFiles = list_files(fn.file.toPath());
                        List<Path> encFiles = allFiles.stream().filter(p -> p.getFileName().toString().endsWith(".enc")).collect(Collectors.toList());
                        publish("Decrypting folder: " + fn.file.getAbsolutePath() + " (" + encFiles.size() + " .enc files)");
                        decrypt_folder(encFiles, pwd, this::publish);
                        publish("Folder decrypted: " + fn.file.getAbsolutePath());
                        write_log("DECRYPT_FOLDER", fn.file.getAbsolutePath());
                    } catch (SecurityException se) {
                        publish("Decryption failed: wrong password or corrupted file. Operation aborted.");
                    } catch (Exception ex) {
                        publish("Folder decryption error: " + ex.getMessage());
                    } finally {
                        Arrays.fill(pwd, '\0');
                    }
                    return null;
                }
                protected void process(List<String> chunks) { 
                    for (String m: chunks) {
                        append_status(m); 
                    }
                }
                protected void done() { 
                    refresh(); 
                }
            };
            w.execute();
        } else {
            Path in = fn.file.toPath();
            String name = in.getFileName().toString();
            if (!name.endsWith(".enc")) {
                append_status("Please select an encrypted file (ends with .enc) to decrypt.");
                return;
            }
            // file-level: a fixed ky/password is used
            char[] pwd = "default-file-key".toCharArray(); //built-in password for single file encryption/decryption
            SwingWorker<Void, String> w = new SwingWorker<>() {
                protected Void doInBackground() {
                    try {
                        Path tmpOut = in.getParent().resolve(name.substring(0, name.length() - 4));
                        publish("Decrypting: " + in);
                        decrypt_file(in, tmpOut, pwd);
                        Files.deleteIfExists(in);
                        publish("File restored: " + tmpOut);
                        write_log("DECRYPT_FILE", in.toString());
                    } catch (SecurityException se) {
                        publish("Decryption failed: wrong password or corrupted file.");
                    } catch (Exception ex) {
                        publish("Decryption error: " + ex.getMessage());
                    } finally {
                        Arrays.fill(pwd, '\0');
                    }
                    return null;
                }
                protected void process(List<String> chunks) { 
                    for (String m: chunks) {
                        append_status(m); 
                    }
                }
                protected void done() { 
                    refresh(); 
                }
            };
            w.execute();
        }
    }

    //What happens when I press the 'View Logs' button (Viewing the actions that have been taken)
    private void selecting_view_logs() {
        SwingWorker<Void, Void> w = new SwingWorker<>() {
            protected Void doInBackground() {
                if (!Files.exists(LOG_FILE)) {
                    append_status("No log file found (" + LOG_FILE.toAbsolutePath() + ").");
                    return null;
                }
                try {
                    String log = Files.readString(LOG_FILE, StandardCharsets.UTF_8);
                    SwingUtilities.invokeLater(() -> {
                        JTextArea ta = new JTextArea(log, 30, 80);
                        ta.setEditable(false);
                        JOptionPane.showMessageDialog(EncryptionGUI.this, new JScrollPane(ta), "Logs", JOptionPane.INFORMATION_MESSAGE);
                    });
                    append_status("Log displayed.");
                } catch (IOException ex) {
                    append_status("Error reading log file: " + ex.getMessage());
                }
                return null;
            }
        };
        w.execute();
    }

    
    //Helper function for encrypting single files.
    private void encrypt_file(Path in, Path out, char[] pwd) throws Exception {
        // obtaining key
        SecretKeySpec key = key_from_password(pwd);

        //creating the hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream is = Files.newInputStream(in)) {
            byte[] buf = new byte[64 * 1024];
            int r;
            while ((r = is.read(buf)) != -1) {
                md.update(buf, 0, r);
            }
        }
        byte[] plaintextHash = md.digest();

        // cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // write header (FENC + stored hash) to out, then ciphertext
        Files.createDirectories(out.getParent());
        try (InputStream is = Files.newInputStream(in);
             OutputStream os = Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
             CipherOutputStream cos = new CipherOutputStream(os, cipher)) {
            os.write(FILE_MAGIC);
            os.write(plaintextHash);

            // now write ciphertext via cos (which will write to os after header)
            byte[] buf = new byte[64 * 1024];
            int r;
            while ((r = is.read(buf)) != -1) {
                cos.write(buf, 0, r);
            }
            cos.flush();
        }
    }

    //Helper function for decrypting single files.
    private void decrypt_file(Path inEnc, Path out, char[] pwd) throws Exception {
        long inSize = Files.size(inEnc);
        if (inSize < FILE_MAGIC.length + HASH_LEN) {
            throw new IOException("Encrypted file too small / invalid format.");
        }

        SecretKeySpec key = key_from_password(pwd);

        try (InputStream fis = Files.newInputStream(inEnc)) {
            byte[] magic = new byte[FILE_MAGIC.length];
            if (fis.read(magic) != magic.length) throw new IOException("Failed reading header.");
            if (!Arrays.equals(magic, FILE_MAGIC)) throw new IOException("Not an encrypted file (magic mismatch).");

            // read stored plaintext hash
            byte[] storedHash = new byte[HASH_LEN];
            if (fis.read(storedHash) != storedHash.length) throw new IOException("Failed reading stored hash.");

            // decrypt remainder while hashing plaintext
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            Files.createDirectories(out.getParent());
            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 OutputStream os = Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {

                byte[] buf = new byte[64 * 1024];
                int r;
                while ((r = cis.read(buf)) != -1) {
                    os.write(buf, 0, r);
                    md.update(buf, 0, r);
                }
                os.flush();
            } catch (Exception ex) {
                // on failure remove partial output
                try { Files.deleteIfExists(out); } catch (Exception ignored) {}
                throw new IOException("Decryption failed (bad password or corrupted data): " + ex.getMessage(), ex);
            }

            byte[] computed = md.digest();
            if (!Arrays.equals(computed, storedHash)) {
                Files.deleteIfExists(out);
                throw new SecurityException("Decryption failed: password mismatch or file corrupted (integrity check failed).");
            }
        }
    }

    //creating a key from password
    private SecretKeySpec key_from_password(char[] pwd) throws Exception {
        byte[] pwdBytes = new String(pwd).getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(pwdBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }


    private List<Path> list_files(Path folder) throws IOException {
        try (Stream<Path> s = Files.walk(folder)) {
            return s.filter(Files::isRegularFile).collect(Collectors.toList());
        }
    }

    //Helper function for encrypting folders
    private void encrypt_folder(List<Path> filesToEncrypt, char[] pwd, java.util.function.Consumer<String> progress) throws Exception {
        for (Path file : filesToEncrypt) {
            String nm = file.getFileName().toString();
            // skip existing encrypted files
            if (nm.endsWith(".enc")) {
                continue;
            }
            Path out = file.resolveSibling(nm + ".enc");
            try {
                progress.accept("Encrypting: " + file);
                encrypt_file(file, out, pwd);
                Files.deleteIfExists(file); // only remove original after success
            } catch (Exception ex) {
                // failed encryption
                progress.accept("Failed to encrypt " + file + ": " + ex.getMessage());
                throw ex; // abort on first failure
            }
        }
    }

    //Helper function for decrypting folders
    private void decrypt_folder(List<Path> encFiles, char[] pwd, java.util.function.Consumer<String> progress) throws Exception {
        // process files in list order and track restored files so we can rollback if password is wrong
        List<Path> restored = new ArrayList<>();
        try {
            for (Path enc : encFiles) {
                String nm = enc.getFileName().toString();
                if (!nm.endsWith(".enc")){
                    continue;
                }
                Path out = enc.resolveSibling(nm.substring(0, nm.length() - 4));
                try {
                    progress.accept("Decrypting: " + enc);
                    decrypt_file(enc, out, pwd);
                    Files.deleteIfExists(enc);
                    restored.add(out);
                } catch (SecurityException se) {
                    // wrong password entered or the file is corrupted
                    progress.accept("Password mismatch or corrupted file detected at: " + enc);
                    for (Path r : restored) try { Files.deleteIfExists(r); } catch (Exception ignored) {}
                    throw se;
                } catch (Exception ex) {
                    // decryption failed
                    progress.accept("Failed to decrypt " + enc + ": " + ex.getMessage());
                    for (Path r : restored) try { Files.deleteIfExists(r); } catch (Exception ignored) {}
                    throw ex;
                }
            }
        } finally {
            // do nothing
        }
    }

    //Creating logs
    private void write_log(String action, String path) {
        try {
            String entry = String.format("%s|%s|%s%n", action, path, sdf.format(new Date()));
            Files.writeString(LOG_FILE, entry, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            append_status("Log written.");
        } catch (IOException ex) {
            append_status("Failed to write log: " + ex.getMessage());
        }
    }

    //Converts file size into a readable format (e.g. using units like B, KB, MB, GB)
    private String readable_size(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        return String.format("%.1f %ciB", bytes / Math.pow(1024, exp), "KMGTPE".charAt(exp - 1));
    }

    //Main function (Required for compiling and running the application)
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            EncryptionGUI app = new EncryptionGUI();
            app.setVisible(true);
        });
    }

    //Helper class that simplifies the display and working with files and folders displayed in the left pane of the GUI (aka the tree)
    private static class FileNode {
        final File file;
        FileNode(File f) { 
            this.file = f; 
        }
        public String toString() { 
            String n = file.getName(); 
            return n.isEmpty() ? file.getAbsolutePath() : n; 
        }
    }
}