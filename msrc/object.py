from dataclasses import dataclass, field, InitVar, is_dataclass, asdict
from functools import partial
from typing import (
    TypeVar,
    NewType,
    List,
    Dict,
    Any,
    get_type_hints,
    Optional,
    Union,
    Tuple,
    get_origin,
    get_args,
)
from functools import reduce

""" Default Type """


@dataclass
class Base:
    data: InitVar[Dict] = None

    def __post_init__(self, data=Dict[str, Any]):
        if not data:
            return
        for fieldname, field_ in self.__dataclass_fields__.items():
            if fieldname in data:
                if "mapper" in field_.metadata:
                    mapper = field_.metadata["mapper"]
                    value = mapper(data[fieldname])
                else:
                    value = data[fieldname]
                object.__setattr__(self, fieldname, value)


CommonType = NewType("CommonType", str)
CommonType.set_value = lambda t: t.get("Value", "") if isinstance(t, dict) else ""
commontype_field = partial(field, default="", metadata={"mapper": CommonType.set_value})


DocumentPublisherType = TypeVar("DocumentPublisherType", bound="DocumentPublisher")


@dataclass
class DocumentPublisher(Base):
    ContactDetails: CommonType = commontype_field()
    IssuingAuthority: CommonType = commontype_field()
    Type: int = 0


IdentificationType = TypeVar("IdentificationType", bound="Identification")


@dataclass
class Identification(Base):
    ID: CommonType = commontype_field()
    Alias: CommonType = commontype_field()


@dataclass
class RevisionHistory(Base):
    Number: str = ""
    Date: str = ""
    Description: CommonType = commontype_field()

    @staticmethod
    def mapper(data: List[Dict]):
        return [RevisionHistory(data=rev) for rev in data]


@dataclass
class DocumentNote(Base):
    Title: str = field(default="")
    Audience: str = field(default="")
    Type: str = field(default="")
    Ordinal: str = field(default="")
    Value: str = field(default="")

    @staticmethod
    def mapper(data: List["DocumentNote"]):
        return [DocumentNote(data=d) for d in data]


DocumentTrackingType = TypeVar("DocumentTrackingType", bound="DocumentTracking")


@dataclass
class DocumentTracking(Base):
    Identification: IdentificationType = field(
        default=None, metadata={"mapper": lambda d: Identification(data=d)}
    )
    Status: int = 0
    Version: str = "1.0"
    RevisionHistory: List["RevisionHistory"] = field(
        default_factory=list, metadata={"mapper": RevisionHistory.mapper}
    )
    InitialReleaseDate: str = ""
    CurrentReleaseDate: str = ""


@dataclass
class Item(Base):
    ProductID: str = ""
    Value: str = ""

    @staticmethod
    def mapper(data: Dict[str, Any]):
        return [Item(data=prod) for prod in data]


@dataclass
class Items(Base):
    Items: List[Item] = field(default_factory=list, metadata={"mapper": Item.mapper})

    @staticmethod
    def mapper(data: Dict[str, Any]):
        return [Items(data=d) for d in data]


@dataclass
class Branch(Base):
    Items: List["Items"] = field(
        default_factory=list, metadata={"mapper": Items.mapper}
    )
    Type: str = "0"
    Name: str = ""

    @staticmethod
    def mapper(data: Dict[str, Any]):
        return [Branch(data=branch) for branch in data]


@dataclass
class FullProductName(Base):
    ProductID: str = ""
    Value: str = ""

    @staticmethod
    def mapper(data: Dict[str, Any]):
        return [FullProductName(data=prod) for prod in data]


ProductTreeType = TypeVar("ProductTreeType", bound="ProductTree")


@dataclass
class ProductTree(Base):
    Branch: List["Branch"] = field(
        default_factory=list, metadata={"mapper": Branch.mapper}
    )
    FullProductName: List["FullProductName"] = field(
        default_factory=list, metadata={"mapper": FullProductName.mapper}
    )


@dataclass
class Note(Base):
    Title: str = ""
    Type: str = ""
    Ordinal: str = "0"
    Value: str = ""

    @staticmethod
    def mapper(data: List[Dict]):
        return [Note(data=d) for d in data]


@dataclass
class ProductStatus(Base):
    ProductID: List[str] = field(default_factory=list)
    Type: str = "0"

    @staticmethod
    def mapper(data: List[Dict]):
        return [ProductStatus(data=d) for d in data]


@dataclass
class Threat(Base):
    Description: CommonType = commontype_field()
    ProductID: List[str] = field(default_factory=list)
    Type: str = "0"
    DateSpecified: bool = False

    @staticmethod
    def mapper(data: List[Dict]):
        return [Threat(data=d) for d in data]


@dataclass
class CVSSScoreSet(Base):
    BaseScore: float = 0.0
    TemporalScore: float = 0.0
    Vector: str = ""
    ProductID: List[str] = field(default_factory=list)

    @staticmethod
    def mapper(data: List[Dict]):
        return [CVSSScoreSet(data=d) for d in data]


@dataclass
class Remediation(Base):
    Description: CommonType = commontype_field()
    URL: str = ""
    Supercedence: str = ""
    ProductID: List[str] = field(default_factory=list)
    Type: str = "0"
    DateSpecified: bool = False
    AffectedFiles: List[str] = field(default_factory=list)
    RestartRequired: CommonType = commontype_field()
    SubType: str = ""
    FixedBuild: str = ""

    @staticmethod
    def mapper(data: List[Dict]):
        return [Remediation(data=d) for d in data]


@dataclass
class Acknowledgment(Base):
    @staticmethod
    def mapper(data: List[Dict]):
        return [Acknowledgment(data=d) for d in data]


VulnerabilityType = TypeVar("VulnerabilityType", bound="Vulnerability")


@dataclass
class Vulnerability(Base):
    Title: CommonType = commontype_field()
    Notes: List[Note] = field(default_factory=list, metadata={"mapper": Note.mapper})
    DiscoveryDateSpecified: bool = False
    ReleaseDateSpecified: bool = False
    CVE: str = ""
    ProductStatuses: List[ProductStatus] = field(
        default_factory=list, metadata={"mapper": ProductStatus.mapper}
    )
    Threats: List[Threat] = field(
        default_factory=list, metadata={"mapper": ProductStatus.mapper}
    )
    CVSSScoreSets: List[CVSSScoreSet] = field(
        default_factory=list, metadata={"mapper": CVSSScoreSet.mapper}
    )
    Remediations: List[Remediation] = field(
        default_factory=list, metadata={"mapper": Remediation.mapper}
    )
    Acknowledgments: List[Acknowledgment] = field(
        default_factory=list, metadata={"mapper": RevisionHistory.mapper}
    )
    Ordinal: str = "0"
    RevisionHistory: List["RevisionHistory"] = field(
        default_factory=list, metadata={"mapper": RevisionHistory.mapper}
    )

    @staticmethod
    def mapper(data: List["Vulnerability"]):
        return [Vulnerability(data=d) for d in data]
    


CVRFType = TypeVar("CVRFType", bound="CVRF")


@dataclass
class CVRF(Base):
    DocumentTitle: CommonType = commontype_field(default=None)
    DocumentType: CommonType = commontype_field(default=None)
    DocumentPublisher: DocumentPublisherType = field(
        default=None, metadata={"mapper": lambda d: DocumentPublisher(data=d)}
    )
    DocumentTracking: DocumentTrackingType = field(
        default=None, metadata={"mapper": lambda d: DocumentTracking(data=d)}
    )
    ProductTree: ProductTreeType = field(
        default=None, metadata={"mapper": lambda d: ProductTree(data=d)}
    )
    DocumentNotes: List[DocumentNote] = field(
        default_factory=list, metadata={"mapper": DocumentNote.mapper}
    )
    Vulnerability: List[VulnerabilityType] = field(
        default_factory=list, metadata={"mapper": Vulnerability.mapper}
    )

    def get_cve(self, cve_id: str) -> Optional[VulnerabilityType]:
        """ Find, and get a CVE data """
        for vuln in self.Vulnerability:
            if vuln.CVE == cve_id:
                return vuln
        return None
