import pyshark
import logging
from binascii import unhexlify
from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_core.elt import Element
from pycrate_asn1dir import NGAP
from pycrate_asn1rt.utils import get_obj_at
import pycrate_core.elt
from typing import Iterator



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Recursive function to extract paths and values from a NAS5G Element
def getPathsFromNAS5G(element: Element) -> list[tuple[list[str], any]]:
    paths = []
    try:
        if element.CLASS in ["Envelope", "Alt", "Sequence"]:
            for next_item in element._content:
                if next_item.CLASS == 'Atom':
                    if next_item._val is None and next_item._trans:
                        continue
                    path = next_item.fullname().split(".")
                    val = next_item._val
                    if isinstance(val, bytes):
                        val = val.hex()
                    paths.append((path, val))
                    # Handle inner NASMessage recursively
                    if next_item._name == "NASMessage" and isinstance(next_item._val, bytes):
                        inner_pdu, err = parse_NAS5G(next_item._val)
                        if inner_pdu and inner_pdu.CLASS in ["Envelope", "Alt", "Sequence"]:
                            inner_paths = getPathsFromNAS5G(inner_pdu)
                            for ipath, ival in inner_paths:
                                paths.append((path + ipath, ival))
                elif next_item.CLASS in ['Envelope', 'Alt', 'Sequence']:
                    paths += getPathsFromNAS5G(next_item)
                else:
                    logger.warning(f"Unhandled element class: {next_item.CLASS}")
        else:
            logger.debug(f"Unhandled root element class: {element.CLASS}")
    except AttributeError as e:
        logger.debug(f"AttributeError: {e}")
    return paths



# A dict that maps NAS Type to a function that matches the target IE path
target_fields = {
	"RES": lambda path: "RES" in path and path[-1] == "L",
	"NAS_KSI": lambda path: "NAS_KSI" in path and path[-1] == "Value",
	"5GSRegType": lambda path: "5GSRegType" in path and path[-1] == "Value",
	"5GSID": lambda path: "5GSID" in path and path[-1] == "Type",
	"UESecCap": lambda path: "UESecCap" in path and path[-1] == "L",
	"NASSecAlgo": lambda path: "NASSecAlgo" in path and path[-1] == "IntegAlgo",
	"PayloadContainer": lambda path: "PayloadContainer" in path and path[-1] == "L" and path[-2] == "PayloadContainer",
	"PayloadContainerType": lambda path: "PayloadContainerType" in path and path[-1] == "V",
	# Add more as needed
}


def extract_basic_pdu_info(paths, packet_data, all_keys):

    epd_count = 0
    sechdr_count = 0
    type_count = 0
    GMMCause_count = 0
    seqn_recorded = False
    spare_count = 0

    for path, value in paths:
        key = path[-1]

        # EPD (Extended Protocol Discriminator)
        if key == "EPD":
            epd_count += 1
            epd_key = f"EPD_{epd_count}" if epd_count > 1 else "EPD"
            packet_data[epd_key] = value
            all_keys.add(epd_key)
            print(f"{epd_key}: {value}")
            
        elif path[-1] == 'spare' and (path[-2] == '5GMMHeader' or path[-2] == "5GMMHeaderSec"):
            spare_count += 1
            spare_key = f"spare_{spare_count}" if spare_count > 1 else "spare"
            packet_data[spare_key] = value
            all_keys.add(spare_key)
            print(f"{spare_key}: {value}")
       

        # SecHdr
        elif key == "SecHdr":
            sechdr_count += 1
            sechdr_key = f"SecHdr_{sechdr_count}" if sechdr_count > 1 else "SecHdr"
            packet_data[sechdr_key] = value
            all_keys.add(sechdr_key)
            print(f"{sechdr_key}: {value}")

        # Seqn – only one per packet, optional
        elif key == "Seqn" and not seqn_recorded:
            packet_data["Seqn"] = value
            all_keys.add("Seqn")
            print(f"Seqn: {value}")
            seqn_recorded = True
            
        # (or path[-2] == '5GSMHeader')
        elif path[-2] == '5GMMHeader' and path[-1] == 'Type':
            type_count += 1
            type_key = f"Type_{type_count}" if type_count > 1 else "Type"
            packet_data[type_key] = value
            all_keys.add(type_key)
            print(f"{type_key}: {value}")
            
        for field_name, match_fn in target_fields.items():
            if match_fn(path):
                packet_data[field_name] = str(value)
                all_keys.add(field_name)
                print(f"{field_name}: {value}")

        # 5GMMCause – handle after the above checks
        if key == "5GMMCause":
            GMMCause_count += 1
            GMMCause_key = f"5GMMCause_{GMMCause_count}" if GMMCause_count > 1 else "5GMMCause"
            packet_data[GMMCause_key] = value
            all_keys.add(GMMCause_key)
            print(f"{GMMCause_key}: {value}")

    return packet_data



# ===========================================================================================
# =
# =
# =         The below function is to extract the ngap layer for the live packet
# =
# =
# =
# =
# =
# =
# =
# =
# =
# ===========================================================================================

# Returns absolute paths so that we can then use "set_val_at()" function to change the value we wanted.
# In case multiple paths match, all of them will be returned.
# This is NOT EFFICIENT (O(n*m)), but this is the only way I have found to have a general function that can find this.

def returnPathsFromEndpoint(paths: Iterator, endpoint:str) -> list:
    """
    Returns the list of all paths to a given ressource, where the ressource "endpoint" is given by its name.
   
    Flaw:
        Do note that one endpoint can have multiple paths.
        eg. path1 = [a, b, c, d] and path2 = [e, d, f, g] both have d as endpoint, and so both the paths will be returned.
   
    Args:
        paths: Iterator of paths, where paths are of the form (path, value), and path is a non-empty list of values.
        endpoint: name of the element we are getting the path of.
 
    Returns:
        valid_paths: list of all paths that contain the endpoint name. Can be empty.
    """
    valid_paths:list[list] = []
    for path in paths:
        if endpoint in path[0]: # Actual path, path[1] is endpoint value. We could think about getting path[1] too if we wanted the value.
            valid_paths.append(path[0])
   
    return valid_paths

def getNASmessage(pdu:pycrate_core.elt.Element):
    """
    Extract the NAS message from a NGAP message.
    Args:
        pdu: the Protocol Description Unit of the NGAP message we want to extract the NAS message from.
    Returns:
        output: None if no NAS message present. Else, output the NAS message element of NGAP as an ASN1 ATOM.
    """
    output = None
    paths = returnPathsFromEndpoint(pdu.get_val_paths(),"NAS-PDU")
    if len(paths)!=0:
        #output = pdu.get_val_at(paths[0])
        output = get_obj_at(pdu, paths[0])
    return output
 

 
def isSublist(sublist:list, main_list:list):
    """
    Checks if sublist is part of the main list, in order. E.g. [e,f], [a,d,f,e,g] and [e,f], [e,d,g,a,f] will return False, [e,f], [a,d,e,f,g] will return True.
 
    Args:
        sublist: list of elements. Will be checked against main_list.
        main_list: list of elements.
 
    Returns:
        True if sublist is part of main_list, else False.
   
    """
    f_isSublist = False
    try:
        initial_indexes = [i for i in range(len(main_list)) if sublist[0]==main_list[i]]
        for index in initial_indexes:
            assert len(sublist) <= len(main_list) - index
            f_isSublist = True
            for i in range(len(sublist)):
                if sublist[i]!=main_list[index+i]:
                    f_isSublist = False
                    break
            if f_isSublist: # We know that this is a sublist, immediately exit.
                break
    except Exception as e:
        logger.error("isSublist" > str(e))
        f_isSublist = False
    return f_isSublist
