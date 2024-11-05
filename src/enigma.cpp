#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <vector>
#include "./include/CLI11.hpp"
using namespace std;

template <typename T, size_t N>
void shuffle(array<T, N> &arr, mt19937 &gen);

int machineSubcommand(const string &configFile, const optional<int> &seed);
int encodeSubcommand(const string &configFile, const optional<string> &inputFile, const optional<string> &outputFile, const string &eRotorConfig, const optional<string> &ePlugConfig);

int getFileSize(ifstream& File);

void verifyRotor(array<int, 26> &rotor, int i);
void verifyReflector(array<int, 26> &reflector);

void encryptMessage(array<array<int, 3>, 3> &rotorConfig, array<array<array<int, 26>, 2>, 5> &rotors, array<int, 26> &reflector, const optional<string> &inputFile, const optional<string> &outputFile);

template <int N>
class Rotor {
  array<int, N> fCons;
  array<int, N> bCons;
  int cIndex = 0;
  int iIndex = 0;

  public:
    Rotor(array<array<int, N>, 2> rotor, int c, int i) {
      this->fCons = rotor[0];
      this->bCons = rotor[1];

      this->cIndex = c;
      this->iIndex = i;
    }

    Rotor() : cIndex(0), iIndex(0) {
      iota(fCons.begin(), fCons.begin(), 0);
      bCons.fill(0);
    }

  public:
    int getFCon(int c) {
      return (this->fCons[(c + this->cIndex) % N] + this->cIndex) % N;
    }

    int getBCon(int c) {
      int con = c - this->cIndex;
      if (con < 0) {
        con += N;
      }

      int val = this->bCons[con] - this->cIndex;
      if (val < 0) {
        val += N;
      }

      return val;
    }

    bool rotate() {
      bool rotateNext = this->cIndex == this->iIndex;

      this->cIndex = (cIndex + 1) % N;

      return rotateNext;
    }

    void shuffle(array<int, N> &arr, mt19937 &gen) {
      for (int i = N; i > 1; i--) {
        uniform_int_distribution<int> dis(0, i - 1);

        swap(arr[i - 1], arr[dis(gen)]);
      }
    }
};

template <int N>
class Reflector {
  array<int, N> reflector;

  public:
  Reflector(array<int, N> reflector) {
    this->reflector = reflector;
  }

  Reflector() {
    this->reflector.fill(0);
  }

  int reflect(int c) {
    return this->reflector[c];
  }
};

class Encoder {
  array<Rotor<26>, 3> rotors;
  Reflector<26> reflector;

  public:
  Encoder(array<array<int, 3>, 3> &rotorConfig, array<array<array<int, 26>, 2>, 5> &rotors, array<int, 26> &reflector) {
    for (int i = 0; i < 3; i++) {
      this->rotors[i] = Rotor<26>(rotors[rotorConfig[i][0] - 1], rotorConfig[i][1] - 1, rotorConfig[i][2] - 1);
    }

    this->reflector = Reflector<26>(reflector);
  }

  void index() {
    if (this->rotors[0].rotate()) {
      if (this->rotors[1].rotate()) {
        this->rotors[2].rotate();
      }
    }
  }

  string encode(string message) {
    string cipher;
    for (char &c : message) {
      c = tolower(c);

      if (c >= 97 && c <= 122) {
        c -= 97;

        for (int i = 0; i < 3; i++) {
          c = this->rotors[i].getFCon(c);
        }
        c = this->reflector.reflect(c);
        for (int i = 2; i >= 0; i--) {
          c = this->rotors[i].getBCon(c);
        }

        cipher += (c + 97);
        this->index();
      } else {
        cipher += c;
      }
    }

    return cipher;
  }
};

int main(int argc, char **argv) {
  // encode
    // -c {machine config file}
    // -i {optional, plain text file}
    // -o {optional, ciphered text file}
    // -r 1:12:34,4:16:12,5:1:4 {rotor:position:indexing position, ...}
    // -p a-z,p-y,... {optional, 0...10}
  // machine
    // -s {optional, seed}
    // -o {machine config file}

  CLI::App app{"A program that accurately mimics the first version of the Enigma Machine."};
  app.require_subcommand(1);

  // Encoding command section
  auto encode_cmd = app.add_subcommand("encode", "Encode a message");
  string eConfig;
  encode_cmd -> add_option("-c,--config", eConfig, "The file that holds the machine config") -> required();
  optional<string> eInputFile;
  encode_cmd -> add_option("-i,--input", eInputFile, "The file that holds text to be encrypted");
  optional<string> eOutputFile;
  encode_cmd -> add_option("-o,--output", eOutputFile, "The file that will hold the encrypted text");
  string eRotorConfig;
  encode_cmd -> add_option("-r,--rotor_config", eRotorConfig, "A string that holds the rotor configuration") -> required();
  optional<string> ePlugConfig;
  encode_cmd -> add_option("-p,--plugboard_config", ePlugConfig, "A string that holds the plugboards' configuration");

  // Machine command section
  auto machine_cmd = app.add_subcommand("machine", "Create a new machine");
  string mOutputFile;
  machine_cmd -> add_option("-o,--output", mOutputFile, "The file that will hold the machines' configuration") -> required();
  optional<int> mSeed;
  machine_cmd -> add_option("-s,--seed", mSeed, "An integer to use as the rng's seed");

  CLI11_PARSE(app, argc, argv);

  if (encode_cmd -> parsed()) {
    return encodeSubcommand(eConfig, eInputFile, eOutputFile, eRotorConfig, ePlugConfig);
  } else if (machine_cmd -> parsed()) {
    return machineSubcommand(mOutputFile, mSeed);
  }

  return 0;
}

int machineSubcommand(const string &configFile, const optional<int> &seed) {
  mt19937 gen;

  if (!seed) {
    random_device rd;
    gen = mt19937(rd());
  } else {
    gen = mt19937(seed.value());
  }

  array<int, 26> connections = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25
  };


  // .enig file definition
    // [0x00, 0x19] Rotor 1 definition
    // [0x1A, 0x33] Rotor 2 definition
    // [0x34, 0x4D] Rotor 3 definition
    // [0x4E, 0x67] Rotor 4 definition
    // [0x68, 0x81] Rotor 5 definition
    // [0x82, 0x9B] Reflector definition

  ofstream File(configFile);

  // Generate 5 random rotors
  for (int i = 0; i < 5; i++) {
    array<int, 26> rotor = connections;
    shuffle(rotor, gen);

    for (int num : rotor) {
      File << (char) num;
    }
  }

  array<int, 26> reflector;
  vector<int> options = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25 };
  // Generate random reflector
  for (int i = 0; i < 13; i++) {
    array<int, 2> cons;
    for (int j = 0; j < 2; j++) {
      uniform_int_distribution<int> dis(0, options.size() - 1);

      int rNum = dis(gen);
      cons[j] = options[rNum];
      options.erase(options.begin() + rNum);
    }

    reflector[cons[0]] = cons[1];
    reflector[cons[1]] = cons[0];
  }
  // Write the generated reflector
  for (int num : reflector) {
    File << (char) num;
  }

  File.close();

  return 0;
}

int encodeSubcommand(const string &configFile, const optional<string> &inputFile, const optional<string> &outputFile, const string &eRotorConfig, const optional<string> &ePlugConfig) {
  regex pattern("([1-5]):(2[0-6]|1[0-9]|[1-9]):(2[0-6]|1[0-9]|[1-9]),([1-5]):(2[0-6]|1[0-9]|[1-9]):(2[0-6]|1[0-9]|[1-9]),([1-5]):(2[0-6]|1[0-9]|[1-9]):(2[0-6]|1[0-9]|[1-9])");

  smatch matches;
  if (regex_match(eRotorConfig, pattern)) {
    regex_search(eRotorConfig, matches, pattern);

    array<array<int, 3>, 3> rotorConfig;
    if (matches[1] != matches[4] && matches[1] != matches[7] && matches[4] != matches[7]) {
      for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
          rotorConfig[i][j] = stoi(matches[i*3 + j + 1]);
        }
      }
    } else {
      throw runtime_error("You can only use each rotor once in the configuration.");
    }

    ifstream File(configFile);

    int size = getFileSize(File);

    if (size == 156) {
      array<array<array<int, 26>, 2>, 5> rotors;
      array<int, 26> reflector;

      char byte;

      for (int i = 0; i < 6; i++) {
        for (int j = 0; j < 26; j++) {
          File.get(byte);

          if (i == 5) {
            reflector[j] = byte;
          } else {
            rotors[i][0][j] = byte;
            rotors[i][1][byte] = j;
          }
        }
      }

      // Verification of imported bits from file
      verifyReflector(reflector);
      int i = 0;
      for (array<array<int, 26>, 2> rotor : rotors) {
        verifyRotor(rotor[0], i);
        i++;
      }

      encryptMessage(rotorConfig, rotors, reflector, inputFile, outputFile);
    } else {
      cout << "Machine config file does not have the correct amount of bytes." << endl;
      cout << "File has " << size << " bytes, but needs 156." << endl;

      return 1;
    }
  } else {
    cout << "Incorrect rotor config." << endl;

    return 1;
  }
  return 0;
}

template <typename T, size_t N>
void shuffle(array<T, N> &arr, mt19937 &gen) {
  for (int i = N; i > 1; i--) {
    uniform_int_distribution<int> dis(0, i - 1);

    swap(arr[i - 1], arr[dis(gen)]);
  }
}

int getFileSize(ifstream& File) {
  File.seekg(0, ios::end);
  int size = File.tellg();
  File.seekg(0, ios::beg);
  return size;
}

void verifyRotor(array<int, 26> &rotor, int i) {
  vector<int> values = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25
  };

  for (int num : rotor) {
    vector<int>::iterator it = find(values.begin(), values.end(), num);
    if (it != values.end()) {
      values.erase(it);
    } else {
      throw runtime_error("Rotor " + to_string(i + 1) + " did not pass validation.");
    }
  }
}

void verifyReflector(array<int, 26> &reflector) {
  vector<int> values = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25
  };

  int i = 0;
  for (int num : reflector) {
    if (i != reflector[num] || num == i) {
      throw runtime_error("Reflector did not pass validation.");
    }

    i++;
  }
}

void encryptMessage(array<array<int, 3>, 3> &rotorConfig, array<array<array<int, 26>, 2>, 5> &rotors, array<int, 26> &reflector, const optional<string> &inputFile, const optional<string> &outputFile) {
  string message;
  if (!inputFile) {
    cout << "Message: ";
    getline(cin, message);
  } else {
    ifstream File(inputFile.value());

    ostringstream buffer;
    buffer << File.rdbuf();
    message = buffer.str();
    File.close();
  }

  Encoder encoder = Encoder(rotorConfig, rotors, reflector);

  string cipher = encoder.encode(message);

  if (!outputFile) {
    cout << cipher << endl;
  } else {
    ofstream File(outputFile.value());

    for (char c : cipher) {
      File << c;
    }

    File.close();
  }
}