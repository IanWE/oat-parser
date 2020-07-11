#pragma once

#include <string>
#include <map>
#include <memory>
#include <list>
#include <bits/unique_ptr.h>
#include "OATHeader.h"
#include "class_status.h"
#include "../art/compiler_filter.h"

namespace Art {
    class DexHeader;

    class OATHeader;

    class DexFile; 


class OATParser {
  public:
        OATParser() { };

        OATParser(const char *a_oat, unsigned int a_size);

        ~OATParser();

        static OATParser &GetInstance();

        void init(const char *a_oat_file, const char *a_out_dex_path);

        uint8_t *Begin() const;

        uint8_t *End() const;
        //const uint8_t *End_(){return m_oat_end};

        bool Parser();

        bool ParserOatToGetSignature(const char *oat_file, std::string *signature, CompilerFilter::Filter *filter, int *dex_count);

        bool ParserMultiOats();

        const char* GetStoreValueByKey(const char *key_string, const char* key, const int size);

        const char* GetCompilerFilter(const char *key_string, int key_string_size);

        void SetToGenerateSignature(bool is_signature_generated) {
            m_is_signature_generated = is_signature_generated;
        }

        void SetToGenerateSecurestore(bool is_securestore_generated) {
            m_is_securestore_generated = is_securestore_generated;
        }

        void SetToDoIV(bool is_do_IV) {
            m_is_do_IV = is_do_IV;
        }

        bool isGenerateSignature() {
            return m_is_signature_generated;
        }

        bool isGenerateSecurestore() {
            return m_is_securestore_generated;
        }

        bool isDoIV() {
            return m_is_do_IV;
        }

        bool ParseSecureStore(const char *securestore_file, int dex_count);

        bool DoIV(const std::string signature, CompilerFilter::Filter filter);

	bool ParseOatFile(const std::string read_file);

	bool TamperChecksum(const std::string tamper_file);

	size_t Size() const {
    	  return End() - Begin();
	}

        //const std::string& GetLocation() const {
        //  return location_;
        //}

      class OatMethod final {
        public:
          OatMethod(const uint8_t* base, const uint32_t code_offset): begin_(base), code_offset_(code_offset) {}
	  OatMethod(const OatMethod&) = default;
	  ~OatMethod() {}
	  OatMethod& operator=(const OatMethod&) = default;
          // A representation of an invalid OatMethod, used when an OatMethod or OatClass can't be found.
          // See ClassLinker::FindOatMethodFor.
          static const OatMethod Invalid() {
            return OatMethod(nullptr, -1);
          }
	  const uint32_t GetOffset() {
	    return code_offset_;
	  }
	private:
          template<class T>
          T GetOatPointer(uint32_t offset) const {
            if (offset == 0) {
              return nullptr;
            }
            return reinterpret_cast<T>(begin_ + offset);
          }
          const uint8_t* begin_;
          uint32_t code_offset_;
          friend class OatClass;
        };

      class OatClass final {
        public:
        //ClassStatus GetStatus() const {
        int16_t GetStatus() const {
          return status_;
        }
        OatClassType GetType() const {
          return type_;
        }
	const OatMethod GetOatMethod(uint32_t method_index) const;
	const OatMethodOffsets* GetOatMethodOffsets(uint32_t method_index) const;
	uint32_t GetOatMethodOffsetsOffset(uint32_t method_index) const;
	private:
	OATParser::OatClass::OatClass(const OATParser* oat_file,
                            //ClassStatus status,
                            int16_t status,
                            OatClassType type,
                            uint32_t bitmap_size,
                            const uint32_t* bitmap_pointer,
                            const OatMethodOffsets* methods_pointer)
        : oat_file_(oat_file), status_(status), type_(type),
          bitmap_(bitmap_pointer), methods_pointer_(methods_pointer) {}

             const OATParser* const oat_file_;
         
             //const ClassStatus status_;
             const int16_t status_;
         
             const OatClassType type_;
         
             const uint32_t* const bitmap_;
         
             const OatMethodOffsets* const methods_pointer_;
         
             friend class Art::OatDexFile;
           };

    private:
        bool OpenOat(std::unique_ptr<char[]> &a_buf, unsigned int &a_len);

        bool OatReSet(std::unique_ptr<char[]> &a_buf);

        bool Dump(int index, const DexHeader *a_dex_header);

        bool DumpSignature(FILE *f, const uint32_t signature);

        const OATHeader *GetOatHeader() {
            return m_oatheader.get();
        };

        void MakeDexName(int index, std::string &a_out_dex_name);

    private:
        static OATParser m_oat_parser;
	std::vector<const OatDexFile*> oat_dex_files_storage_;
	// Cache of dex files mapped directly from a location, in case the OatFile does
        // not embed the dex code.
	std::unique_ptr<std::vector<std::unique_ptr<const DexFile>>> uncompressed_dex_files_;
        std::unique_ptr<OATHeader> m_oatheader;//store oat header
        std::string m_oat_file;
        std::string m_out_dex_path;

        const uint8_t *m_oat_begin;//begin
        const uint8_t *m_oat_end;//end, value is unchangeable

        bool m_is_signature_generated;
        bool m_is_securestore_generated;
        bool m_is_do_IV;

        std::map<CompilerFilter::Filter, std::string> secure_store_map_;

	std::list<uint32_t> dex_file_checksums_;
};//OATParser

class OatDexFile {
  public:
  uint32_t GetOatClassOffset(uint16_t class_def_index) const {
    return oat_class_offsets_pointer_[class_def_index];
  }
  OATParser::OatClass OatDexFile::GetOatClass(uint16_t class_def_index) const;
  
  private:
  OatDexFile(const OATParser* oat_file,
             const std::string& dex_file_location,
             const std::string& canonical_dex_file_location,
             uint32_t dex_file_checksum,
             const uint8_t* dex_file_pointer,
             const uint8_t* lookup_table_data,
             const IndexBssMapping* method_bss_mapping,
             const IndexBssMapping* type_bss_mapping,
             const IndexBssMapping* string_bss_mapping,
             const uint32_t* oat_class_offsets_pointer,
             const DexLayoutSections* dex_layout_sections);
    // Create an OatDexFile wrapping an existing DexFile. Will set the OatDexFile
  // pointer in the DexFile.
  OatDexFile(const OATParser* oat_file,
             const DexFile* dex_file,
             const std::string& dex_file_location,
             const std::string& canonical_dex_file_location);
  bool IsBackedByVdexOnly() const;
  
  static void AssertAotCompiler();
  
  const OATParser* const oat_file_ = nullptr;//we do not use OatFile
  const std::string dex_file_location_;
  const std::string canonical_dex_file_location_;
  const uint32_t dex_file_location_checksum_ = 0u;
  const uint8_t* const dex_file_pointer_ = nullptr;
  const uint8_t* const lookup_table_data_ = nullptr;
  const IndexBssMapping* const method_bss_mapping_ = nullptr;
  const IndexBssMapping* const type_bss_mapping_ = nullptr;
  const IndexBssMapping* const string_bss_mapping_ = nullptr;
  const uint32_t* const oat_class_offsets_pointer_ = nullptr;
  TypeLookupTable lookup_table_;
  const DexLayoutSections* const dex_layout_sections_ = nullptr;
  
  friend class OATParser;
  DISALLOW_COPY_AND_ASSIGN(OatDexFile);
};//OatDexFile

}//Art
