

import hashlib
import os
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
import struct
import json


INPUTFILE = os.path.join(os.path.dirname(__file__), os.pardir, 'inputs.json')
INPUTFILE_KEYS = ['ProductCarbonFootprints', 'Recipe', 'Suppliers', 'verified']

OUTPUTFILE = os.path.join(os.path.dirname(__file__), os.pardir, 'artifacts', 'witness-parameters.txt')

# Returns R, S, M0, M1
def format_signature(sig):
    
    "Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file."
    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S]
    args = " ".join(map(str, args))

    return args

def read_input_file(filepath):
 
    with open(filepath, "r") as f:
        
        input_content = json.load(f)
        
        for key in INPUTFILE_KEYS:
            assert input_content.get(key) is not None, f"Missing {key} field in input.json!"
        
        verified = zip([pcf[0] for pcf in input_content.get('ProductCarbonFootprints')], input_content.get('verified'))    
        return [
            input_content.get('ProductCarbonFootprints'),
            input_content.get('Recipe'),
            input_content.get('Suppliers'),
            list(verified)]
        
def write_output_file(filepath, outputString):
    
    with open(filepath, "w") as f:
        f.write(outputString)
        

def publicKey_to_string(publicKey: PublicKey) -> str:
    return str(publicKey.p.x.n) + " " + str(publicKey.p.y.n)


def createFootprintOutput(value: int, materialId: int, privateKey: PrivateKey = None):
    """
    Takes a carbon footprint value as input,
    returns a list of strings formatted as zokrates inputs:
    1. raw value in bytes
    2. signature parameters
    3. publicKey
    """
    if not privateKey:
        privateKey = PrivateKey.from_rand()
    
    publicKey = PublicKey.from_private(privateKey)

    bytesValue = int.to_bytes(value, 64, 'big')

    bytesMaterialId = int.to_bytes(materialId , 64, 'big')

    hashedValue = hashlib.sha256(bytesValue).digest()\
                + hashlib.sha256(bytesMaterialId).digest()

    bytesTotal = bytesValue + bytesMaterialId

    signedValue = privateKey.sign(hashedValue)

    rawFormattedValue = " ".join([str(i) for i in struct.unpack(">32I", bytesTotal)])

    formattedSignature = format_signature(signedValue)

    formattedPublicKey = publicKey_to_string(publicKey)

    print(f"ProductCarbonFootprint (MatId: {materialId}): {value}\nSigned by {PublicKey.from_private(privateKey)}\n")
    
    return rawFormattedValue, formattedSignature, formattedPublicKey

def parseRecipe(array):

    bytesValues = b''
    for item in array:
        bytesValues += int.to_bytes(item, 4, 'big')

    bufferlength = 16 - len(array)
    bytesValues += int.to_bytes(0, 4, 'big') * bufferlength

    hashedValue = hashlib.sha256(bytesValues).digest()

    rawFormattedValue = " ".join([str(i) for i in struct.unpack(">16I", bytesValues)])

    return rawFormattedValue, hashedValue

def createSupplierOutput(materialId: int, supplierId: int,  privateKey: PrivateKey = None):
    """
    Takes a carbon footprint value as input,
    returns a list of strings formatted as zokrates inputs:
    1. raw value in bytes
    2. signature parameters
    3. publicKey
    """
    if not privateKey:
        privateKey = PrivateKey.from_rand()
    
    publicKey = PublicKey.from_private(privateKey)


    bytesMaterialId = int.to_bytes(materialId , 64, 'big')

    bytesSupplierId = int.to_bytes(supplierId , 64, 'big')

    hashedValue =  hashlib.sha256(bytesMaterialId).digest()\
                + hashlib.sha256(bytesSupplierId).digest()
    
    bytesTotal = bytesMaterialId + bytesSupplierId

    signedValue = privateKey.sign(hashedValue)

    rawFormattedValue = " ".join([str(i) for i in struct.unpack(">32I", bytesTotal)])

    formattedSignature = format_signature(signedValue)

    formattedPublicKey = publicKey_to_string(publicKey)

    print(f"SupplierID (MatId: {materialId}): {supplierId}\nSigned by {PublicKey.from_private(privateKey)}\n")
    
    return rawFormattedValue, formattedSignature, formattedPublicKey

def createSuppliersOutputs(inputSuppliers):

    rawSuppliers, signedSuppliers, auditorSuppliers = "","",""

    for i, (materialId, supplierId) in enumerate(inputSuppliers):

        rawSupplier, signedSupplier, auditorSupplier = createSupplierOutput(materialId, supplierId)

        rawSuppliers = " ".join([rawSuppliers, rawSupplier])
        signedSuppliers = " ".join([signedSuppliers, signedSupplier])
        auditorSuppliers = " ".join([auditorSuppliers, auditorSupplier])


    return rawSuppliers, signedSuppliers, auditorSuppliers



def createRecipeOutput(recipeWhole, privateKey: PrivateKey = None):

    recipe = [weight[1] for weight in recipeWhole]
    materialIds = [weight[0] for weight in recipeWhole]
    
    arrayLength = len(recipe)

    if not privateKey:
        privateKey = PrivateKey.from_rand()
    
    print(f"Recipe: \n\tWeights: \t{recipe}\n\tMaterialIds: \t{materialIds}\nSigned by {PublicKey.from_private(privateKey)}\n")
    
    if arrayLength <= 16:
        return createRecipeOutputFor1(recipe, materialIds, privateKey=privateKey)
    
    if len(recipe) % 16 != 0:
        bufferAmount = 16 - len(recipe)%16
        recipe.extend([0 for _ in range(bufferAmount)])
        materialIds.extend([0 for _ in range(bufferAmount)])

    raw = signed =  pkey = ""
    for i in range(arrayLength//16 + 1):
        newRaw, newSigned, newPkey = createRecipeOutputFor1(
            recipe[i*16:(i+1)*16],
            materialIds[i*16:(i+1)*16],
            privateKey=privateKey
        )
        raw = " ".join([raw, newRaw])
        signed = " ".join([signed, newSigned])
        pkey = " ".join([pkey, newPkey])
    
    
    return raw, signed, pkey
        

def createRecipeOutputFor1(recipe: list, materialIds: list, privateKey: PrivateKey = None):
    
    """
    Signes a hash that is created from 
    """
    if not privateKey:
        privateKey = PrivateKey.from_rand()
    
    publicKey = PublicKey.from_private(privateKey)

    rawRecipe, hashRecipe = parseRecipe(recipe)

    rawMaterialIds, hashMaterialIds = parseRecipe(materialIds)

    hashedValue = hashRecipe + hashMaterialIds

    signedValue = privateKey.sign(hashedValue)

    rawFormattedValue = rawRecipe + " " + rawMaterialIds

    formattedSignature = format_signature(signedValue)

    formattedPublicKey = publicKey_to_string(publicKey)

    # vprint(rawFormattedValue+', '+  str(len(rawFormattedValue.split(' '))))

    return rawFormattedValue, formattedSignature, formattedPublicKey

def createFootprintOutputs(pcfs):

    rawPCFs, signedPCFs, auditorPCFs = "","",""

    for materialId, pcf in pcfs:

        rawPCF, signedPCF, auditorPCF = createFootprintOutput(pcf, materialId)

        rawPCFs = " ".join([rawPCFs, rawPCF])
        signedPCFs = " ".join([signedPCFs, signedPCF])
        auditorPCFs = " ".join([auditorPCFs, auditorPCF])

    return rawPCFs, signedPCFs, auditorPCFs

def createVerifiedTagsOutput(verified):
    verifiedTags = ""
    for materialId, boolean in verified:
        _verified = 1 if boolean else 0 
        verifiedTags = " ".join([verifiedTags, (str(materialId) + " " + str(_verified))])
        if not _verified:
            print(f"Value (MatId: {materialId}): UNVERIFIED!")
    return verifiedTags


def main():

    inputPCF, inputRecipe, inputSuppliers, inputVerified = read_input_file(INPUTFILE)

    rawRecipe, signedRecipe, auditorRecipe = createRecipeOutput(inputRecipe)
    rawSupplierIds, signedSupplierList, auditorSupplier  =  createSuppliersOutputs(inputSuppliers)
    rawPCFs, signedPCFs, auditorPCFs = createFootprintOutputs(inputPCF)

    verifiedTags = createVerifiedTagsOutput(inputVerified)
    
    stringOutput = " ".join([
        rawRecipe,
        signedRecipe,
        auditorRecipe,
        rawPCFs,
        signedPCFs,
        auditorPCFs,
        rawSupplierIds, 
        signedSupplierList,
        auditorSupplier,
        verifiedTags
    ])

    write_output_file(OUTPUTFILE, stringOutput)
    print(f"Written data to witness parameter file!")

if __name__ == "__main__":
    main()


