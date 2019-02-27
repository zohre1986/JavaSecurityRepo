import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

public class BillionLOLs {

    // For a complete prevention list, see:
    // https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet

    public static void main(String[] args)
            throws ParserConfigurationException,
            IOException, SAXException {


        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(UnMarshalling.class.getResource("billion-laughs.xml").getFile());
        Element root = doc.getDocumentElement();

        System.out.printf("Root: %s\n", root.getTagName());
        System.out.println("Done.");

    }
}