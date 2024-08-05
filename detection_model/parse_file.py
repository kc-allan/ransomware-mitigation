import pefile
import hashlib
import pandas as pd
import math

def calculate_md5(file_path):
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()

def calculate_sections_mean_entropy(pe):
    entropies = [section_entropy(section) for section in pe.sections]
    return sum(entropies) / len(entropies) if entropies else 0

def calculate_sections_min_entropy(pe):
    entropies = [section_entropy(section) for section in pe.sections]
    return min(entropies) if entropies else 0

def calculate_sections_max_entropy(pe):
    entropies = [section_entropy(section) for section in pe.sections]
    return max(entropies) if entropies else 0

def calculate_sections_mean_rawsize(pe):
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    return sum(raw_sizes) / len(raw_sizes) if raw_sizes else 0

def calculate_sections_min_rawsize(pe):
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    return min(raw_sizes) if raw_sizes else 0

def calculate_sections_max_rawsize(pe):
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    return max(raw_sizes) if raw_sizes else 0

def calculate_sections_mean_virtualsize(pe):
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    return sum(virtual_sizes) / len(virtual_sizes) if virtual_sizes else 0

def calculate_sections_min_virtualsize(pe):
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    return min(virtual_sizes) if virtual_sizes else 0

def calculate_sections_max_virtualsize(pe):
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    return max(virtual_sizes) if virtual_sizes else 0

def calculate_imports_nb_dll(pe):
    return len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0

def calculate_imports_nb(pe):
    imports = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports += len(entry.imports)
    return imports

def calculate_imports_nb_ordinal(pe):
    ordinals = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            ordinals += len([imp for imp in entry.imports if imp.ordinal])
    return ordinals

def calculate_export_nb(pe):
    return len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0

def calculate_resources_nb(pe):
    return len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0

def calculate_resources_mean_entropy(pe):
    entropies = [resource_entropy(resource) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return sum(entropies) / len(entropies) if entropies else 0

def calculate_resources_min_entropy(pe):
    entropies = [resource_entropy(resource) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return min(entropies) if entropies else 0

def calculate_resources_max_entropy(pe):
    entropies = [resource_entropy(resource) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return max(entropies) if entropies else 0

def calculate_resources_mean_size(pe):
    sizes = [len(resource.data) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return sum(sizes) / len(sizes) if sizes else 0

def calculate_resources_min_size(pe):
    sizes = [len(resource.data) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return min(sizes) if sizes else 0

def calculate_resources_max_size(pe):
    sizes = [len(resource.data) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return max(sizes) if sizes else 0

def section_entropy(section):
    data = section.get_data()
    return entropy(data)

def resource_entropy(resource):
    data = resource.data
    return entropy(data)

def entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)

def get_file_metadata(file_path):
    pe = pefile.PE(file_path)
    file_info = {
        'Name': file_path,
        'md5': calculate_md5(file_path),
        'Machine': pe.FILE_HEADER.Machine,
        'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
        'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
        'BaseOfData': pe.OPTIONAL_HEADER.BaseOfData if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData') else 0,
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'Win32VersionValue': pe.OPTIONAL_HEADER.Win32VersionValue if hasattr(pe.OPTIONAL_HEADER,
                                                                            'Win32VersionValue') else 0,
        'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
        'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
        'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        'SectionsMeanEntropy': calculate_sections_mean_entropy(pe),
        'SectionsMinEntropy': calculate_sections_min_entropy(pe),
        'SectionsMaxEntropy': calculate_sections_max_entropy(pe),
        'SectionsMeanRawSize': calculate_sections_mean_rawsize(pe),
        'SectionsMinRawSize': calculate_sections_min_rawsize(pe),
        'SectionsMaxRawSize': calculate_sections_max_rawsize(pe),
        'SectionsMeanVirtualSize': calculate_sections_mean_virtualsize(pe),
        'SectionsMinVirtualSize': calculate_sections_min_virtualsize(pe),
        'SectionsMaxVirtualSize': calculate_sections_max_virtualsize(pe),
        'ImportsNbDLL': calculate_imports_nb_dll(pe),
        'ImportsNb': calculate_imports_nb(pe),
        'ImportsNbOrdinal': calculate_imports_nb_ordinal(pe),
        'ExportsNb': calculate_export_nb(pe),
        'ResourcesNb': calculate_resources_nb(pe),
        'ResourcesMeanEntropy': calculate_resources_mean_entropy(pe),
        'ResourcesMinEntropy': calculate_resources_min_entropy(pe),
        'ResourcesMaxEntropy': calculate_resources_max_entropy(pe),
        'ResourcesMeanSize': calculate_resources_mean_size(pe),
        'ResourcesMinSize': calculate_resources_min_size(pe),
        'ResourcesMaxSize': calculate_resources_max_size(pe),
    }
    return file_info
