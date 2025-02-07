package gr.hcg.controllers;

import com.google.gson.JsonObject;
import gr.hcg.check.PDFSignatureInfo;
import gr.hcg.check.PDFSignatureInfoParser;
import gr.hcg.services.UploadDocumentService;
import gr.hcg.sign.Signer;
import gr.hcg.views.JsonView;
import org.bouncycastle.tsp.TSPException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.naming.InvalidNameException;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.core.io.ByteArrayResource;

@Controller
public class SignController {

    @Value("${check.config}")
    private String checkConfig;

    @Value("${signer.apikey}")
    private String signerapikey;

    @Value("${signer.docsUrlPrefix}")
    private String docsUrlPrefix;

    @Autowired
    Signer signer;

    @Autowired
    UploadDocumentService uploadDocumentService;

    @GetMapping("/sign")
    public ModelAndView home(Model model) {
        model.addAttribute("message", "Please upload a pdf file to sign");
        model.addAttribute("config", checkConfig);
        return new ModelAndView("sign", model.asMap());

    }

    private ResponseEntity<byte[]> respondHtmlOrJson(Optional<Boolean> json, Model model, HttpServletResponse response) {
        if (json.isPresent()) {
            // Assuming JsonView.Render() returns a byte[] representation of the JSON.
            byte[] jsonData = JsonView.Render(model, response);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            return new ResponseEntity<>(jsonData, headers, HttpStatus.OK);
        } else {
            // Convert the HTML response to bytes and return.
            // This part might need further adjustments based on how you handle HTML responses.
            byte[] htmlData = "HTML response here".getBytes(StandardCharsets.UTF_8); // Placeholder
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_HTML);
            return new ResponseEntity<>(htmlData, headers, HttpStatus.OK);
        }
    }

    @PostMapping("/sign")
    public  ResponseEntity<byte[]> singleFileUpload(Model model,
                                   @RequestParam(value = "file") MultipartFile file,
                                   @RequestParam(value = "apikey") String apikey,
                                   @RequestParam(value = "password") Optional<String> password,
                                   HttpServletResponse response ) {

        Optional<Boolean> json = Optional.of(true);
        model.addAttribute("uuid", null);
        model.addAttribute("path", null);
        if (file.isEmpty()) {
            model.addAttribute("message", "Empty file");
            model.addAttribute("error", true);
            return respondHtmlOrJson(json, model, response);
        }

        if(!apikey.equals(signerapikey)) {
            model.addAttribute("message", "Wrong api key");
            model.addAttribute("error", true);
            return respondHtmlOrJson(json, model, response);
        }


        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            Calendar signDate;
            if(password.isPresent()){
                signDate=signer.sign(file.getInputStream(), bos, password.orElse(""));
            } else {
                signDate=signer.sign(file.getInputStream(), bos);
            }

            // Get the signed PDF bytes
            byte[] signedPdfBytes = bos.toByteArray();

            // Set headers for the response
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "signed_document.pdf");
            headers.setCacheControl("must-revalidate, post-check=0, pre-check=0");

            // Return the signed PDF in the response
            return new ResponseEntity<>(signedPdfBytes, headers, HttpStatus.OK);

        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | IllegalStateException e) {
            model.addAttribute("error", true);
            model.addAttribute("message", "Error: " + e.getMessage());
            e.printStackTrace();
            //return "sign";
            return respondHtmlOrJson(json, model, response);
        }

    }
}