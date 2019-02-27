import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.stream.StreamSource;

public class UnMarshalling {

    // For a complete prevention list, see:
    // https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet

    public static void main(String[] args) throws Exception {
        JAXBContext jc = JAXBContext.newInstance(Customer.class);

        XMLInputFactory xif = XMLInputFactory.newFactory();

//        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
//        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);

        XMLStreamReader xsr = xif.createXMLStreamReader(
                new StreamSource(UnMarshalling.class.getResource("myFile.xml").getFile()));

        Unmarshaller unmarshaller = jc.createUnmarshaller();
        Customer customer = (Customer) unmarshaller.unmarshal(xsr);

        Marshaller marshaller = jc.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(customer, System.out);
    }

}