
#include "bristol_executor.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/timer.h>
#include <vector>

static uint32_t* pos_even;
static uint32_t* pos_odd;


int32_t exec_bristol_circuit(std::string& circuit, uint32_t input_gates, e_role role, const std::string& address, uint16_t port, seclvl seclvl,
                             uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing,
                             bool verbose, bool insecure) {
	uint32_t bitlen = 32;
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 10000);
    assert(sharing == S_BOOL || sharing == S_YAO);
	std::vector<Sharing*>& sharings = party->GetSharings();
    if(insecure) {
        assert(sharing == S_BOOL);
        sharings[S_BOOL]->SetPreCompPhaseValue(ePreCompInsecure);
    }

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	CBitVector key, verify;

    CBitVector inputs;
    inputs.Create(nvals * input_gates, crypt);

    // lol, that's how it's done in the other examples... ¯\_(ツ)_/¯
    BooleanCircuit* circ = (BooleanCircuit*) sharings[sharing]->GetCircuitBuildRoutine();


    share* s_in;
    s_in = circ->PutSIMDINGate(nvals, inputs.GetArr(), input_gates, CLIENT);

    auto out = circ->PutGateFromFile(circuit, s_in->get_wires(), nvals);


    e_role key_inputter;

//    s_key = circ->PutRepeaterGate(input_blocks,s_key);

//    auto s_out = BuildAESCircuit(s_in_all, s_key, (BooleanCircuit*) circ);

    party->ExecCircuit();

//    CBitVector out(input_blocks * AES_BITS);
//
//    if(role == CLIENT) {
//        for(auto block = 0; block < input_blocks; block++) {
//            auto out_ptr = s_out[block]->get_clear_value_ptr();
//            out.SetBytes(out_ptr, block * AES_BYTES, AES_BYTES);
//        }
//    }



    PrintTimingsJson();
    PrintCommunicationJson();

	delete crypt;
	delete party;

//	free(output);
	return 0;
}

std::vector<share*> BuildAESCircuit(std::vector<share*> in_blocks, share* key, BooleanCircuit* circ) {
    share *chaining_state = circ->PutINGate(uint32_t(0), AES_BITS, CLIENT);
    std::vector<share *> out_shares(in_blocks.size());

    for (auto i = 0; i < in_blocks.size(); i++) {
        auto inp = circ->PutXORGate(in_blocks[i], chaining_state);
        auto inp_ids = inp->get_wires();
        for(auto key_id: key->get_wires()) {
            inp_ids.push_back(key_id);
        }
        auto t = circ->PutGateFromFile(std::string("../../bin/circ/AES-non-expanded.aby"), inp_ids);
        delete chaining_state;
        chaining_state = new boolshare(t, circ);
        out_shares[i] = new boolshare(circ->PutOUTGate(t, CLIENT), circ);
    }

    return out_shares;
}

void verify_AES_encryption(uint8_t* input, uint8_t* key, uint32_t nvals, uint8_t* out, crypto* crypt) {
	AES_KEY_CTX* aes_key = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
	crypt->init_aes_key(aes_key, key);
	for (uint32_t i = 0; i < nvals; i++) {
		crypt->encrypt(aes_key, out + i * AES_BYTES, input + i * AES_BYTES, AES_BYTES);
	}
	free(aes_key);
}
