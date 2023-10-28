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

    //private ResponseEntity<byte[]> handleUpload(String year, String folder, String protocol, String uuid, byte[] bytes) throws IOException {
    private JsonObject handleUpload(String year, String authority, String folder, String protocol, String uuid, byte[] bytes) throws IOException {
        String path = uploadDocumentService.handleUpload(year, authority, folder, protocol, uuid, bytes);

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        JsonObject jo = new JsonObject();
        jo.addProperty("uuid", uuid);
        jo.addProperty("path", path);
        return jo;


        //return new ResponseEntity<>(jo.toString().getBytes(StandardCharsets.UTF_8), headers, HttpStatus.OK);
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
                                   @RequestParam(value = "year") String year,
                                   @RequestParam(value = "protocol") String protocol,
                                   @RequestParam(value = "authority") String authority,
                                   @RequestParam(value = "folder") String folder,
                                   @RequestParam(value = "apikey") String apikey,
                                   @RequestParam(value = "signed") Optional<Boolean> signed,
                                   @RequestParam(value = "json") Optional<Boolean> json,
                                   @RequestParam(value = "signName") Optional<String> signName,
                                   @RequestParam(value = "signReason") Optional<String> signReason,
                                   @RequestParam(value = "signLocation") Optional<String> signLocation,
                                   @RequestParam(value = "visibleLine1") Optional<String> visibleLine1,
                                   @RequestParam(value = "visibleLine2") Optional<String> visibleLine2,

                                   // @RequestParam(value = "qrcode") Optional<String> qrcode,
                                   HttpServletResponse response ) {

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
        if(year==null || protocol == null || authority == null || folder == null || year.equals("") || protocol.equals("") || folder.equals("")  || authority.equals("")) {
            model.addAttribute("message", "Fill year, authority, folder and protocol");
            model.addAttribute("error", true);
            return respondHtmlOrJson(json, model, response);
        }

        final String uuid = UUID.randomUUID().toString();

        if (signed.orElse(false) == true) {
            // Handle signed file
            byte[] bytes;
            try {
                bytes = file.getBytes();
                List<PDFSignatureInfo> info = PDFSignatureInfoParser.getPDFSignatureInfo(bytes);
                if (info.isEmpty()) {
                    model.addAttribute("error", true);
                    model.addAttribute("message", "Cannot find siganture");
                } else {
                    JsonObject jo = handleUpload(year, authority, folder, protocol, uuid, bytes);
                    model.addAttribute("path", jo.get("path"));
                    model.addAttribute("uuid", jo.get("uuid"));
                    return respondHtmlOrJson(json, model, response);
                }

            } catch (IOException | InvalidNameException | CertificateException | NoSuchAlgorithmException |
                     SignatureException | InvalidKeyException | NoSuchProviderException | TSPException e) {

                e.printStackTrace();
                model.addAttribute("error", true);
                model.addAttribute("message", "Cannot validate siganture: " + e.getMessage());
                return respondHtmlOrJson(json, model, response);
            }
            return respondHtmlOrJson(json, model, response);

        } else {
            // Handle non-signed file
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                Calendar signDate = signer.sign(file.getInputStream(), bos);

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




}