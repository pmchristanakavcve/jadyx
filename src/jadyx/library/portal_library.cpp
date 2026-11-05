// SPDX-FileCopyrightText: Copyright 2026 Jadyx Project
// SPDX-License-Identifier: GPL-3.0-or-later
#include "jadyx/library/portal_library.h"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <fmt/format.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "core/memory/cheat_text.h"
#include "core/file_sys/common_funcs.h"
#include "jadyx/cheats/cheat_store.h"
#include "jadyx/content/content_actions.h"
#include "jadyx/content/content_service.h"
#include "jadyx/mods/mod_archive.h"
#include "jadyx/storage/atomic_file.h"
#include "jadyx/storage/storage_path.h"
#include "jadyx/storage/utf8.h"

namespace Jadyx {
namespace {
namespace fs = std::filesystem;
constexpr std::uint64_t MaxSaveImport = 2ULL << 30;
constexpr std::uint64_t MaxCheatText = 4ULL << 20;

std::string PathUtf8(const fs::path& path) {
    const auto text = path.generic_u8string();
    return {text.begin(), text.end()};
}

fs::path PathFromUtf8(std::string_view text) {
    return fs::path{std::u8string{text.begin(), text.end()}};
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string HexDigest(std::string_view text) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(text.data()), text.size(), digest.data());
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (const auto byte : digest) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

std::string SaveKey(std::uint64_t application, const fs::path& save_root, const fs::path& path) {
    return HexDigest(fmt::format("{:016x}/{}", application, PathUtf8(path.lexically_relative(save_root))));
}

std::string RandomSuffix() {
    std::array<unsigned char, 16> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) throw std::runtime_error{"random"};
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

bool IsSafeTree(const fs::path& root, const fs::path& path) {
    const auto relative = path.lexically_normal().lexically_relative(root.lexically_normal());
    if (relative.empty() || relative.is_absolute() || *relative.begin() == "..") return false;
    std::error_code ec;
    auto current = root;
    for (const auto& part : relative) {
        if (part == "." || part == "..") return false;
        current /= part;
        const auto status = fs::symlink_status(current, ec);
        if (ec || fs::is_symlink(status)) return false;
    }
    return true;
}

bool SafeSaveLeaf(std::string_view name) {
    if (name.empty() || name == "." || name == ".." ||
        name.find_first_of("/\\:") != std::string_view::npos ||
        !Mods::SafeRelativePath(name)) return false;
    return name.find_first_of("<>\"|?*") == std::string_view::npos &&
           std::none_of(name.begin(), name.end(), [](unsigned char c) { return c < 32; });
}

bool IsSafeSaveTarget(const fs::path& root, const fs::path& path) {
    if (!SafeSaveLeaf(PathUtf8(path.filename())) || !IsSafeTree(root, path.parent_path())) return false;
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    return (!ec && !fs::is_symlink(status)) || ec == std::errc::no_such_file_or_directory;
}

bool RecognizedSaveName(std::string_view name) {
    const auto lower = Lower(std::string{name});
    return lower.starts_with("gamedata0") || lower.starts_with("autosave") ||
           (lower.starts_with("crystar") && lower.ends_with(".dat")) ||
           lower.ends_with(".dat") || lower.ends_with(".sav") || lower.ends_with(".save") ||
           lower.ends_with(".bin") || lower.ends_with(".sqlite") || lower.ends_with(".db");
}

std::string DataError(Mods::ArchiveError error) {
    switch (error) {
    case Mods::ArchiveError::None: return {};
    case Mods::ArchiveError::TooLarge: return "space";
    case Mods::ArchiveError::Cancelled: return "interrupted";
    case Mods::ArchiveError::Write: return "disk";
    case Mods::ArchiveError::Unreadable:
    case Mods::ArchiveError::Encrypted: return "file";
    }
    return "file";
}

std::string FileLeaf(std::string_view path) {
    const auto slash = path.find_last_of('/');
    return std::string{path.substr(slash == std::string_view::npos ? 0 : slash + 1)};
}

struct RemoveTree {
    fs::path path;
    ~RemoveTree() { std::error_code ignored; fs::remove_all(path, ignored); }
};

struct SaveReplacement {
    fs::path staged, target, backup;
    bool existed{}, published{};
};

std::string PublishSaveFiles(std::vector<SaveReplacement>& files, const fs::path& backup_parent,
                             std::uint64_t application, std::stop_token stop) {
    std::error_code ec;
    std::uint64_t backup_bytes = 0;
    for (auto& file : files) {
        if (stop.stop_requested()) return "interrupted";
        const auto status = fs::symlink_status(file.target, ec);
        if (ec && ec != std::errc::no_such_file_or_directory) return "disk";
        ec.clear();
        file.existed = fs::exists(status);
        if (file.existed && (!fs::is_regular_file(status) || fs::is_symlink(status))) return "file";
        if (file.existed) {
            const auto size = fs::file_size(file.target, ec);
            if (ec || size > MaxSaveImport || backup_bytes > MaxSaveImport - size) return "space";
            backup_bytes += size;
        }
    }
    const auto staging_bytes = [&] {
        std::uint64_t total = 0;
        for (const auto& file : files) {
            const auto size = fs::file_size(file.staged, ec);
            if (ec || size > MaxSaveImport - total) return MaxSaveImport + 1;
            total += size;
        }
        return total;
    }();
    if (staging_bytes > MaxSaveImport) return "space";
    fs::path backup_dir;
    try {
        fs::create_directories(backup_parent, ec);
        if (ec) return "disk";
        std::error_code space_error;
        const auto available = fs::space(backup_parent, space_error).available;
        if (space_error || backup_bytes > std::numeric_limits<std::uint64_t>::max() - staging_bytes ||
            available < backup_bytes + staging_bytes + (16ULL << 20)) return "space";
        backup_dir = backup_parent / fmt::format("{:016x}", application) / RandomSuffix();
        fs::create_directories(backup_dir, ec);
        if (ec) return "disk";
        for (std::size_t i = 0; i < files.size(); ++i) {
            auto& file = files[i];
            if (!file.existed) continue;
            file.backup = backup_dir / (std::to_string(i) + ".bak");
            fs::copy_file(file.target, file.backup, fs::copy_options::none, ec);
            if (ec) return "disk";
        }
        for (auto& file : files) {
            if (stop.stop_requested()) throw std::runtime_error{"interrupted"};
            const auto temporary = fs::path{file.target}.concat(L".jadyx-import.tmp");
            fs::copy_file(file.staged, temporary, fs::copy_options::overwrite_existing, ec);
            if (ec) throw std::runtime_error{"disk"};
            if (file.existed && !fs::remove(file.target, ec)) throw std::runtime_error{"disk"};
            ec.clear();
            fs::rename(temporary, file.target, ec);
            if (ec) throw std::runtime_error{"disk"};
            file.published = true;
        }
    } catch (const std::exception& error) {
        const std::string failure = error.what();
        bool rollback_ok = true;
        for (auto it = files.rbegin(); it != files.rend(); ++it) {
            ec.clear();
            fs::remove(fs::path{it->target}.concat(L".jadyx-import.tmp"), ec);
            ec.clear();
            if (!it->published && !it->existed) continue;
            if (it->published) fs::remove(it->target, ec);
            if (it->existed) {
                ec.clear();
                fs::copy_file(it->backup, it->target, fs::copy_options::overwrite_existing, ec);
                rollback_ok &= !ec;
            }
        }
        return rollback_ok ? failure : "rollback";
    }
    (void)backup_bytes;
    return {};
}
} // namespace

std::uint64_t ContentTagApplication(const std::string& tag) {
    const auto colon = tag.find(':');
    const auto kind = tag.substr(0, colon);
    std::uint64_t application{};
    if (colon == std::string::npos || (kind != "update" && kind != "dlc") ||
        std::from_chars(tag.data() + colon + 1, tag.data() + tag.size(), application, 16).ec != std::errc{})
        return 0;
    return application;
}

std::uint64_t DataTagApplication(const std::string& tag) {
    const auto colon = tag.find(':');
    const auto kind = tag.substr(0, colon);
    const auto end = kind == "save" ? tag.find(':', colon == std::string::npos ? colon : colon + 1) :
                                      std::string::npos;
    if (colon == std::string::npos || (kind != "save" && kind != "cheat") ||
        (kind == "save" && end == std::string::npos)) return 0;
    const auto text = tag.substr(colon + 1, (end == std::string::npos ? tag.size() : end) - colon - 1);
    std::uint64_t application{};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), application, 16);
    if (text.size() != 16 || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) return 0;
    if (kind == "save") {
        const auto folder = tag.substr(end + 1);
        if (folder.size() != 64 || folder.find_first_not_of("0123456789abcdef") != std::string::npos) return 0;
    } else if (tag.find(':', colon + 1) != std::string::npos) {
        return 0;
    }
    return application;
}

PortalLibrarySource::PortalLibrarySource(std::filesystem::path root_, std::filesystem::path cache_directory)
    : root{std::move(root_)}, save_root{Common::FS::GetEdenPath(Common::FS::EdenPath::SaveDir)},
      backup_root{root.parent_path() / "jadyx/save-backups"},
      cache{std::move(cache_directory)} {}

void PortalLibrarySource::Publish(const std::vector<LibraryEntry>& entries, std::uint32_t language_) {
    std::vector<Game> previous;
    {
        std::lock_guard lock{mutex};
        previous = games;
    }
    std::vector<Game> next;
    const auto listed = [&](std::uint64_t application) {
        return std::any_of(next.begin(), next.end(), [&](const auto& g) { return g.info.program_id == application; });
    };
    for (const auto& entry : entries) {
        if (entry.launch_path.empty()) continue;
        if (!entry.title_loaded) {
            // A rescan reads metadata again; keep showing what was known of a dump still present
            // rather than emptying the page until the fill reaches it.
            const auto known = std::find_if(previous.begin(), previous.end(),
                [&](const auto& g) { return g.launch_path == entry.launch_path; });
            if (known != previous.end() && !listed(known->info.program_id)) next.push_back(*known);
            continue;
        }
        if (!entry.program_id) continue;
        const auto application = FileSys::GetBaseTitleID(entry.program_id);
        // One card per game: a second dump of the same title adds nothing to manage.
        if (listed(application)) continue;
        auto files = FindGameFiles(entries, application);
        const bool removable = !files.external;
        next.push_back({.info = {.program_id = application, .name = Utf16ToUtf8(entry.name),
                                 .developer = Utf16ToUtf8(entry.developer),
                                 .version = Utf16ToUtf8(entry.display_version), .removable = removable,
                                 .downloadable = removable},
                        .launch_path = entry.launch_path, .relative_path = entry.relative_path,
                        .build_id = entry.build_id,
                        .files = std::move(files)});
    }
    std::lock_guard lock{mutex};
    if (next == games && language_ == language) return;
    games = std::move(next);
    language = language_;
    ++revision;
}

PortalLibrary PortalLibrarySource::View() {
    return {
        .games = [this] {
            std::lock_guard lock{mutex};
            std::vector<PortalGame> list;
            list.reserve(games.size());
            for (const auto& game : games) list.push_back(game.info);
            return std::pair{revision, std::move(list)};
        },
        .cover = [this](std::uint64_t application) { return Cover(application); },
        .contents = [](std::uint64_t application) {
            Content::Catalog catalog;
            if (Content::DefaultStore().Load(catalog) != Content::Error::None) throw std::runtime_error{"catalog"};
            std::vector<PortalContent> list;
            for (const auto& r : catalog.revisions) {
                if (r.application != application) continue;
                list.push_back({.id = r.id, .kind = r.kind == Content::Kind::Update ? "update" : "dlc",
                                .name = r.name, .version = r.display_version, .title = r.title,
                                .bytes = r.bytes, .enabled = r.enabled, .internal = r.internal});
            }
            return list;
        },
        .saves = [this](std::uint64_t application) { return Saves(application); },
        .game_download = [this](std::uint64_t application) { return GameDownload(application); },
        .save_download = [this](std::uint64_t application, const std::string& file_id) {
            return SaveDownload(application, file_id);
        },
        .progress = [this] { return std::pair{installed.load() >> 20, install_total.load() >> 20}; },
    };
}

std::optional<PortalLibrarySource::Game> PortalLibrarySource::Find(std::uint64_t application) const {
    std::lock_guard lock{mutex};
    const auto found = std::find_if(games.begin(), games.end(),
        [&](const auto& g) { return g.info.program_id == application; });
    if (found == games.end()) return std::nullopt;
    return *found;
}

std::pair<std::vector<PortalSaveFolder>, std::vector<PortalSaveFile>>
PortalLibrarySource::Saves(std::uint64_t application) const {
    std::vector<fs::path> directories;
    for (const auto& path : GameSaveDirectories(save_root, application)) {
        std::error_code ec;
        const auto status = fs::symlink_status(path, ec);
        if (!ec && fs::is_directory(status) && !fs::is_symlink(status) && IsSafeTree(save_root, path))
            directories.push_back(path);
    }
    std::sort(directories.begin(), directories.end(), [&](const auto& left, const auto& right) {
        return PathUtf8(left.lexically_relative(save_root)) < PathUtf8(right.lexically_relative(save_root));
    });

    std::vector<PortalSaveFolder> folders;
    std::vector<PortalSaveFile> files;
    folders.reserve(directories.size());
    for (std::size_t index = 0; index < directories.size(); ++index) {
        const auto& directory = directories[index];
        const auto folder_id = SaveKey(application, save_root, directory);
        folders.push_back({.id = folder_id, .label = std::to_string(index + 1)});
        std::error_code ec;
        fs::recursive_directory_iterator it{directory, fs::directory_options::skip_permission_denied, ec}, end;
        std::size_t count = 0, visited = 0;
        while (!ec && it != end && visited < 10000 && count < 5000) {
            ++visited;
            const auto path = it->path();
            const auto relative = path.lexically_relative(directory);
            const auto status = it->symlink_status(ec);
            if (ec) { ec.clear(); it.increment(ec); continue; }
            if (fs::is_symlink(status)) {
                if (it->is_directory(ec)) it.disable_recursion_pending();
            } else if (fs::is_regular_file(status) && IsSafeTree(save_root, path) &&
                       std::distance(relative.begin(), relative.end()) <= 8) {
                const auto bytes = fs::file_size(path, ec);
                if (!ec && bytes <= MaxSaveImport) {
                    files.push_back({.id = SaveKey(application, save_root, path), .folder = folder_id,
                        .name = PathUtf8(relative), .bytes = bytes, .recognized = RecognizedSaveName(PathUtf8(path.filename()))});
                    ++count;
                }
                ec.clear();
            }
            it.increment(ec);
        }
    }
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        return std::tie(left.folder, left.name) < std::tie(right.folder, right.name);
    });
    return {std::move(folders), std::move(files)};
}

std::optional<PortalDownload> PortalLibrarySource::GameDownload(std::uint64_t application) const {
    const auto game = Find(application);
    if (!game || !game->info.downloadable || game->relative_path.empty() ||
        game->relative_path.is_absolute() || game->relative_path.lexically_normal().empty() ||
        *game->relative_path.lexically_normal().begin() == "..") return std::nullopt;
    const auto path = (root / game->relative_path).lexically_normal();
    if (!IsSafeTree(root, path)) return std::nullopt;
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_regular_file(status)) return std::nullopt;
    const auto extension = Lower(PathUtf8(path.extension()));
    if (extension != ".nsp" && extension != ".xci" && extension != ".nro") return std::nullopt;
    const auto bytes = fs::file_size(path, ec);
    if (ec || bytes == 0) return std::nullopt;
    return PortalDownload{.path = path, .filename = PathUtf8(path.filename()), .bytes = bytes};
}

std::optional<PortalDownload> PortalLibrarySource::SaveDownload(std::uint64_t application,
                                                                const std::string& file_id) const {
    if (file_id.size() != 64 || file_id.find_first_not_of("0123456789abcdef") != std::string::npos)
        return std::nullopt;
    const auto [folders, files] = Saves(application);
    const auto found = std::find_if(files.begin(), files.end(),
        [&](const auto& file) { return file.id == file_id; });
    if (found == files.end()) return std::nullopt;
    const auto directory = std::find_if(folders.begin(), folders.end(),
        [&](const auto& folder) { return folder.id == found->folder; });
    if (directory == folders.end()) return std::nullopt;
    std::vector<fs::path> save_dirs;
    for (const auto& path : GameSaveDirectories(save_root, application)) {
        if (SaveKey(application, save_root, path) == directory->id) {
            save_dirs.push_back(path);
            break;
        }
    }
    if (save_dirs.empty()) return std::nullopt;
    const auto path = (save_dirs.front() / PathFromUtf8(found->name)).lexically_normal();
    if (!IsSafeTree(save_root, path)) return std::nullopt;
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_regular_file(status)) return std::nullopt;
    const auto bytes = fs::file_size(path, ec);
    if (ec || bytes != found->bytes) return std::nullopt;
    return PortalDownload{.path = path, .filename = PathUtf8(path.filename()), .bytes = bytes};
}

std::string PortalLibrarySource::Install(const std::filesystem::path& package, const std::string& tag,
                                         std::stop_token stop, const Content::Progress& progress) {
    // The portal validated the tag when the upload was created; parse it again, never trust it.
    const auto application = ContentTagApplication(tag);
    if (!application) return "file";
    const auto game = Find(application);
    if (!game) return "game";
    return Content::ImportUploadedContent(package, tag.starts_with("update:") ? Content::Kind::Update : Content::Kind::Dlc,
        application, game->launch_path, stop, [&](std::uint64_t done, std::uint64_t total) {
            Progress(done, total);
            if (progress) progress(done, total);
        });
}

std::string PortalLibrarySource::ImportData(const fs::path& file, const std::string& tag, std::stop_token stop) {
    const auto first = tag.find(':');
    if (first == std::string::npos) return "file";
    const auto kind = tag.substr(0, first);
    const auto second = tag.find(':', first + 1);
    const auto application_text = tag.substr(first + 1, second == std::string::npos ? second : second - first - 1);
    std::uint64_t application{};
    const auto parsed = std::from_chars(application_text.data(), application_text.data() + application_text.size(),
                                        application, 16);
    if (application_text.size() != 16 || parsed.ec != std::errc{} ||
        parsed.ptr != application_text.data() + application_text.size()) return "file";
    if (kind == "save") {
        if (second == std::string::npos) return "file";
        const auto folder = tag.substr(second + 1);
        if (folder.size() != 64 || folder.find_first_not_of("0123456789abcdef") != std::string::npos)
            return "file";
        return ImportSave(file, application, folder, stop);
    }
    if (kind == "cheat" && second == std::string::npos) {
        const auto game = Find(application);
        return game ? ImportCheats(file, *game, stop) : "game";
    }
    return "file";
}

std::string PortalLibrarySource::ImportSave(const fs::path& file, std::uint64_t application,
                                             const std::string& folder_id, std::stop_token stop) {
    std::error_code ec;
    std::optional<fs::path> target_folder;
    for (const auto& directory : GameSaveDirectories(save_root, application)) {
        const auto status = fs::symlink_status(directory, ec);
        if (!ec && fs::is_directory(status) && !fs::is_symlink(status) &&
            SaveKey(application, save_root, directory) == folder_id && IsSafeTree(save_root, directory)) {
            target_folder = directory;
            break;
        }
        ec.clear();
    }
    if (!target_folder) return "game";
    if (stop.stop_requested()) return "interrupted";

    std::set<std::string> existing;
    for (fs::directory_iterator it{*target_folder, fs::directory_options::skip_permission_denied, ec}, end;
         !ec && it != end; it.increment(ec)) {
        const auto status = it->symlink_status(ec);
        if (ec) { ec.clear(); continue; }
        if (fs::is_regular_file(status) && !fs::is_symlink(status))
            existing.insert(Lower(PathUtf8(it->path().filename())));
    }
    ec.clear();

    const auto staging = file.parent_path() / "stage" / RandomSuffix();
    fs::create_directories(staging, ec);
    if (ec) return "disk";
    RemoveTree cleanup{staging};
    std::vector<Mods::LayoutFile> archive_files;
    std::vector<std::pair<fs::path, std::string>> staged_names;
    std::uint64_t total = 0;
    const auto add_file = [&](std::string source, std::string name, std::uint64_t bytes) {
        if (!SafeSaveLeaf(name)) return false;
        const auto lower = Lower(name);
        if (!RecognizedSaveName(name) && !existing.contains(lower)) return true;
        if (bytes > MaxSaveImport - total || staged_names.size() >= 1000) return false;
        if (std::any_of(staged_names.begin(), staged_names.end(),
                        [&](const auto& item) { return Lower(item.second) == lower; })) return false;
        total += bytes;
        archive_files.push_back({.from = std::move(source), .to = name, .size = bytes});
        staged_names.emplace_back(fs::path{}, std::move(name));
        return true;
    };

    const auto extension = Lower(PathUtf8(file.extension()));
    if (extension == ".zip") {
        auto source = Mods::OpenFileSource(file);
        if (!source) return "file";
        std::vector<std::unique_ptr<Mods::ArchiveSource>> volumes;
        volumes.push_back(std::move(source));
        const auto listing = Mods::ListArchive(volumes, stop);
        if (listing.error != Mods::ArchiveError::None) return DataError(listing.error);
        if (Lower(listing.format).find("zip") == std::string::npos) return "file";
        for (const auto& item : listing.items) {
            if (!Mods::SafeRelativePath(item.path)) return "file";
            const auto slash = item.path.find_last_of('/');
            const auto name = item.path.substr(slash == std::string::npos ? 0 : slash + 1);
            if (!SafeSaveLeaf(name)) return "file";
            if (!add_file(item.path, name, item.size)) return "file";
        }
        if (archive_files.empty()) return "file";
        const auto error = Mods::ExtractArchive(volumes, archive_files, staging, MaxSaveImport, stop);
        if (error != Mods::ArchiveError::None) return DataError(error);
        for (auto& item : staged_names) item.first = staging / PathFromUtf8(item.second);
    } else {
        const auto name = PathUtf8(file.filename());
        const auto bytes = fs::file_size(file, ec);
        if (ec || bytes > MaxSaveImport || !add_file(name, name, bytes) || staged_names.empty()) return "file";
        const auto staged = staging / PathFromUtf8(staged_names.front().second);
        fs::copy_file(file, staged, fs::copy_options::none, ec);
        if (ec) return "disk";
        staged_names.front().first = staged;
    }
    if (stop.stop_requested()) return "interrupted";

    std::vector<SaveReplacement> replacements;
    replacements.reserve(staged_names.size());
    for (const auto& [staged, name] : staged_names) {
        const auto target = (*target_folder / PathFromUtf8(name)).lexically_normal();
        if (!IsSafeSaveTarget(save_root, target)) return "file";
        replacements.push_back({.staged = staged, .target = target});
    }
    return PublishSaveFiles(replacements, backup_root, application, stop);
}

std::string PortalLibrarySource::ImportCheats(const fs::path& file, const Game& game, std::stop_token stop) {
    if (std::all_of(game.build_id.begin(), game.build_id.end(), [](auto byte) { return byte == 0; }))
        return "build";
    if (stop.stop_requested()) return "interrupted";
    std::array<std::uint8_t, 0x20> build_id{};
    std::copy(game.build_id.begin(), game.build_id.end(), build_id.begin());
    const auto build_name = Cheats::HexId(build_id);
    std::string bytes;
    const auto extension = Lower(PathUtf8(file.extension()));
    if (extension == ".zip") {
        auto source = Mods::OpenFileSource(file);
        if (!source) return "file";
        std::vector<std::unique_ptr<Mods::ArchiveSource>> volumes;
        volumes.push_back(std::move(source));
        const auto listing = Mods::ListArchive(volumes, stop);
        if (listing.error != Mods::ArchiveError::None) return DataError(listing.error);
        if (Lower(listing.format).find("zip") == std::string::npos) return "file";
        std::vector<const Mods::ArchiveItem*> candidates;
        for (const auto& item : listing.items) {
            if (!Mods::SafeRelativePath(item.path)) return "file";
            const auto slash = item.path.find_last_of('/');
            const auto leaf = FileLeaf(item.path);
            const auto dot = leaf.find_last_of('.');
            if (dot != std::string::npos && Lower(leaf.substr(dot)) == ".txt" && Lower(leaf) != "toggles.txt")
                candidates.push_back(&item);
        }
        const Mods::ArchiveItem* chosen = nullptr;
        for (const auto* item : candidates) {
            const auto slash = item->path.find_last_of('/');
            const auto leaf = FileLeaf(item->path);
            if (Lower(leaf) == Lower(build_name + ".txt")) {
                if (chosen) return "file";
                chosen = item;
            }
        }
        if (!chosen && candidates.size() == 1) chosen = candidates.front();
        if (!chosen || chosen->size > MaxCheatText) return "file";
        const auto staging = file.parent_path() / "stage" / RandomSuffix();
        std::error_code ec;
        fs::create_directories(staging, ec);
        if (ec) return "disk";
        RemoveTree cleanup{staging};
        const std::vector<Mods::LayoutFile> selected{{.from = chosen->path, .to = "cheats.txt", .size = chosen->size}};
        const auto error = Mods::ExtractArchive(volumes, selected, staging, MaxCheatText, stop);
        if (error != Mods::ArchiveError::None) return DataError(error);
        std::ifstream input{staging / "cheats.txt", std::ios::binary};
        bytes.assign(std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
        if (input.bad() || bytes.size() != chosen->size) return "file";
    } else if (extension == ".txt") {
        std::error_code ec;
        const auto size = fs::file_size(file, ec);
        if (ec || size > MaxCheatText) return "file";
        std::ifstream input{file, std::ios::binary};
        if (!input) return "file";
        bytes.assign(std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
        if (input.bad() || bytes.size() != size) return "file";
    } else {
        return "file";
    }
    if (stop.stop_requested()) return "interrupted";
    auto entries = Core::Memory::TextCheatParser{}.Parse(bytes);
    if (entries.size() < 2 || Core::Memory::EnabledOpcodeCount(entries) == 0) return "cheat";
    for (auto& entry : entries) entry.enabled = false;

    const auto title_dir = Cheats::TitleLoadDirectory(game.info.program_id);
    const auto folder = title_dir / "Portal import" / "cheats";
    const auto toggles = folder / "toggles.txt";
    const auto cheat_file = folder / PathFromUtf8(build_name + ".txt");
    const auto backup = backup_root.parent_path() / "cheat-backups" /
                        fmt::format("{:016x}", game.info.program_id) / RandomSuffix();
    std::error_code ec;
    fs::create_directories(backup, ec);
    if (ec) return "disk";
    const bool had_toggles = fs::is_regular_file(toggles, ec);
    ec.clear();
    const bool had_cheats = fs::is_regular_file(cheat_file, ec);
    ec.clear();
    if (had_toggles) fs::copy_file(toggles, backup / "toggles.txt", fs::copy_options::none, ec);
    if (ec) return "disk";
    if (had_cheats) fs::copy_file(cheat_file, backup / "cheats.txt", fs::copy_options::none, ec);
    if (ec) return "disk";

    const auto previous_toggles = ReadWholeFile(toggles).value_or(std::string{});
    const auto merged = Cheats::MergeCheatToggles(previous_toggles, entries);
    if (!WriteFileAtomically(toggles, merged)) return "disk";
    if (!WriteFileAtomically(cheat_file, bytes)) {
        if (had_toggles) {
            const auto saved = ReadWholeFile(backup / "toggles.txt");
            if (!saved || !WriteFileAtomically(toggles, *saved)) return "rollback";
        } else {
            fs::remove(toggles, ec);
            if (ec) return "rollback";
        }
        return "disk";
    }
    return {};
}

std::string PortalLibrarySource::Remove(const PortalRemoval& removal) {
    const auto game = Find(removal.application);
    if (!game) return "game";
    return removal.content.empty() ? RemoveGame(root, game->files) :
                                     Content::RemoveContent(removal.application, removal.content);
}

std::optional<std::string> PortalLibrarySource::Cover(std::uint64_t application) {
    const auto found = Find(application);
    if (!found) return std::nullopt;
    const auto& game = *found;
    std::uint32_t game_language{};
    {
        std::lock_guard lock{mutex};
        game_language = language;
    }
    // The cover belongs to the dump: an update/DLC of the game does not invalidate it.
    const auto stamp = IsStoragePath(game.launch_path) ? 0 : LibraryCache::StampFor(root / game.relative_path);
    auto record = cache.Load(game.launch_path, stamp, game_language, true);
    if (!record || record->icon.empty()) return std::nullopt;
    return std::string{record->icon.begin(), record->icon.end()};
}

} // namespace Jadyx
