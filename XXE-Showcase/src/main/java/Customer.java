import lombok.Data;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@Data
class Customer {
    private String name;
    private String data;
}