package gr.hcg.sign;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.logging.Logger;

//@SpringBootApplication
public class Runner implements CommandLineRunner {


    @Autowired
    Signer signer;

    public static void main(String[] args) {
        System.out.println("STARTING THE APPLICATION");

        SpringApplication.run(Runner.class, args);
        System.out.println("APPLICATION FINISHED");
    }


    @Override
    public void run(String... args) throws Exception {
        System.out.println("OK");
        File documentFile = new File("sample3.pdf");
        String name = documentFile.getName();
        String substring = name.substring(0, name.lastIndexOf('.'));
        File signedDocumentFile = new File(documentFile.getParent(), substring + "_signed.pdf");
        FileInputStream fis = new FileInputStream(documentFile);
        FileOutputStream fos = new FileOutputStream(signedDocumentFile);

     int pageNumber = 0;
        float x=0;
        float y=0;
        float width = 250;  // default width
        float height = 100; // default height

        try {
            if (args.length > 0) {
                pageNumber = Integer.parseInt(args[0]);
            }
            if (args.length > 2) {
                x = Integer.parseInt(args[1]);
                y = Integer.parseInt(args[2]);
            }
             if (args.length > 4) {
                width = Float.parseFloat(args[3]);     // ← new: width from args
                height = Float.parseFloat(args[4]);    // ← new: height from args
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input argument(s), using default values.");
        }

        System.out.printf("Signing on page: %d at position (x=%d, y=%d)%n", pageNumber, x, y);
        signer.sign(fis, fos, pageNumber, x, y, width, height);
   
   
    }
}