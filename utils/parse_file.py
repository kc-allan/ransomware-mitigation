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
    """Calculate the mean entropy of all sections in the PE file."""
    entropies = [section_entropy(section) for section in pe.sections]
    return sum(entropies) / len(entropies) if entropies else 0


def calculate_sections_min_entropy(pe):
    """Calculate the minimum entropy of all sections in the PE file."""
    entropies = [section_entropy(section) for section in pe.sections]
    return min(entropies) if entropies else 0


def calculate_sections_max_entropy(pe):
    """Calculate the maximum entropy of all sections in the PE file."""
    entropies = [section_entropy(section) for section in pe.sections]
    return max(entropies) if entropies else 0


def calculate_sections_mean_rawsize(pe):
    """Calculate the mean raw size of all sections in the PE file."""
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    return sum(raw_sizes) / len(raw_sizes) if raw_sizes else 0


def calculate_sections_min_rawsize(pe):
    """Calculate the minimum raw size of all sections in the PE file."""
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    return min(raw_sizes) if raw_sizes else 0


def calculate_sections_max_rawsize(pe):
    """Calculate the maximum raw size of all sections in the PE file."""
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    return max(raw_sizes) if raw_sizes else 0


def calculate_sections_mean_virtualsize(pe):
    """Calculate the mean virtual size of all sections in the PE file."""
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    return sum(virtual_sizes) / len(virtual_sizes) if virtual_sizes else 0


def calculate_sections_min_virtualsize(pe):
    """Calculate the minimum virtual size of all sections in the PE file."""
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    return min(virtual_sizes) if virtual_sizes else 0


def calculate_sections_max_virtualsize(pe):
    """Calculate the maximum virtual size of all sections in the PE file."""
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    return max(virtual_sizes) if virtual_sizes else 0


def calculate_imports_nb_dll(pe):
    """Calculate the number of DLLs imported by the PE file."""
    return len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0


def calculate_imports_nb(pe):
    """Calculate the total number of imports in the PE file."""
    imports = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports += len(entry.imports)
    return imports


def calculate_imports_nb_ordinal(pe):
    """Calculate the number of imports by ordinal."""
    ordinals = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            ordinals += len([imp for imp in entry.imports if imp.ordinal])
    return ordinals


def calculate_export_nb(pe):
    """Calculate the number of exported symbols in the PE file."""
    return len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0


def calculate_resources_nb(pe):
    """Calculate the number of resources in the PE file."""
    return len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0


def calculate_resources_mean_entropy(pe):
    """Calculate the mean entropy of all resources in the PE file."""
    entropies = [resource_entropy(resource) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return sum(entropies) / len(entropies) if entropies else 0


def calculate_resources_min_entropy(pe):
    """Calculate the minimum entropy of all resources in the PE file."""
    entropies = [resource_entropy(resource) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return min(entropies) if entropies else 0


def calculate_resources_max_entropy(pe):
    """Calculate the maximum entropy of all resources in the PE file."""
    entropies = [resource_entropy(resource) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return max(entropies) if entropies else 0


def calculate_resources_mean_size(pe):
    """Calculate the mean size of all resources in the PE file."""
    sizes = [len(resource.data) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return sum(sizes) / len(sizes) if sizes else 0


def calculate_resources_min_size(pe):
    """Calculate the minimum size of all resources in the PE file."""
    sizes = [len(resource.data) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return min(sizes) if sizes else 0


def calculate_resources_max_size(pe):
    """Calculate the maximum size of all resources in the PE file."""
    sizes = [len(resource.data) for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(
        pe, 'DIRECTORY_ENTRY_RESOURCE') else []
    return max(sizes) if sizes else 0


def section_entropy(section):
    """Calculate the entropy of a section."""
    data = section.get_data()
    return entropy(data)


def resource_entropy(resource):
    """Calculate the entropy of a resource."""
    data = resource.data
    return entropy(data)


def entropy(data):
    """Calculate entropy of a given data."""
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
        'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
        'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
        'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        'SectionsNb': len(pe.sections),
        'SectionsMeanEntropy': calculate_sections_mean_entropy(pe),
        'SectionsMinEntropy': calculate_sections_min_entropy(pe),
        'SectionsMaxEntropy': calculate_sections_max_entropy(pe),
        'SectionsMeanRawsize': calculate_sections_mean_rawsize(pe),
        'SectionsMinRawsize': calculate_sections_min_rawsize(pe),
        'SectionsMaxRawsize': calculate_sections_max_rawsize(pe),
        'SectionsMeanVirtualsize': calculate_sections_mean_virtualsize(pe),
        'SectionsMinVirtualsize': calculate_sections_min_virtualsize(pe),
        'SectionsMaxVirtualsize': calculate_sections_max_virtualsize(pe),
        'ImportsNbDLL': calculate_imports_nb_dll(pe),
        'ImportsNb': calculate_imports_nb(pe),
        'ImportsNbOrdinal': calculate_imports_nb_ordinal(pe),
        'ExportNb': calculate_export_nb(pe),
        'ResourcesNb': calculate_resources_nb(pe),
        'ResourcesMeanEntropy': calculate_resources_mean_entropy(pe),
        'ResourcesMinEntropy': calculate_resources_min_entropy(pe),
        'ResourcesMaxEntropy': calculate_resources_max_entropy(pe),
        'ResourcesMeanSize': calculate_resources_mean_size(pe),
        'ResourcesMinSize': calculate_resources_min_size(pe),
        'ResourcesMaxSize': calculate_resources_max_size(pe),
        'LoadConfigurationSize': pe.OPTIONAL_HEADER.DataDirectory[pefile.DIRECTORY_ENTRY['LOAD_CONFIG']].Size,
        'VersionInformationSize': pe.OPTIONAL_HEADER.DataDirectory[pefile.DIRECTORY_ENTRY['VERSION']].Size,
    }
    return file_info

