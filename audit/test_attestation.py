
import attestation
import os

INPUTFILE = os.path.join(os.path.dirname(__file__), os.pardir, 'inputs.json')

def test_file_read():
    
    out = attestation.read_input_file(INPUTFILE)
    
    pcfs, recipe, suppliers, verified = out
    
    assert len(pcfs) == len(recipe) == len(suppliers) == len(verified), "Inputs read from file dont have the same amount of entries!"
    
    for pcf, weight, supplier in zip(pcfs, recipe, suppliers):
        
        assert len(pcf) == 2, "Each PCF needs a MaterialID and Value!"
        assert len(weight) == 2, "Each Weight of a Recipe needs a MaterialID and Value!"
        assert len(supplier) == 2, "Each Supplier needs a MaterialID and Value!"