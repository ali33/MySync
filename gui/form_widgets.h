// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// form_widgets.h - biểu mẫu gắn vào một struct cấu hình: mỗi ô biết cách đẩy giá trị struct -> ô, kiểm ô, và
// gán ô -> struct. Ô sai đổi nền đỏ nhạt + tooltip nguyên thông điệp. Header-only (mẫu).
#include <wx/dirdlg.h>
#include <wx/filedlg.h>
#include <wx/scrolwin.h>
#include <wx/wx.h>

#include <functional>
#include <string>
#include <vector>

#include "form_model.h"
#include "ui_common.h"

namespace mysync::gui {

enum class Browse { None, Dir, FileOpen, FileSave };

template <class T>
class Form {
public:
    using Cur = std::function<T*()>;
    using Check = std::function<std::string(const std::string&)>;

    Form(wxWindow* parent, Cur cur, std::function<void()> on_edit = {})
        : cur_(std::move(cur)), on_edit_(std::move(on_edit)) {
        win_ = new wxScrolledWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL);
        win_->SetScrollRate(0, 12);
        auto* v = new wxBoxSizer(wxVERTICAL);
        grid_ = new wxFlexGridSizer(3, 6, 8);
        grid_->AddGrowableCol(1, 1);
        v->Add(grid_, 1, wxEXPAND | wxALL, 10);
        win_->SetSizer(v);
    }
    wxScrolledWindow* window() { return win_; }
    wxFlexGridSizer* grid() { return grid_; }
    wxWindow* parent() { return win_; }

    // ---- các loại ô
    void text(const char* key, std::function<std::string&(T&)> ref, Check chk = {}, Browse br = Browse::None,
              const char* hint = nullptr, bool required = false) {
        auto* t = new wxTextCtrl(win_, wxID_ANY, "");
        if (hint) t->SetHint(L(hint));
        row(key, t, br);
        Check c = [chk, required](const std::string& s) -> std::string {
            if (required && trim(s).empty()) return tr("err.required");
            return chk ? chk(s) : std::string();
        };
        add(key, t, [t] { return S(t->GetValue()); }, c,
            [t, ref](T& x) { t->ChangeValue(W(ref(x))); }, [t, ref](T& x) { ref(x) = trim(S(t->GetValue())); });
    }

    template <class N>
    void num(const char* key, std::function<N&(T&)> ref, uint64_t lo, uint64_t hi, const char* hint = nullptr) {
        auto* t = new wxTextCtrl(win_, wxID_ANY, "");
        if (hint) t->SetHint(L(hint));
        t->SetMinSize(wxSize(120, -1));
        row(key, t, Browse::None, false);
        Check c = [lo, hi](const std::string& s) { return check_uint(s, lo, hi); };
        add(key, t, [t] { return S(t->GetValue()); }, c,
            [t, ref](T& x) { t->ChangeValue(W(std::to_string(static_cast<unsigned long long>(ref(x))))); },
            [t, ref](T& x) {
                uint64_t v = 0;
                check_uint(S(t->GetValue()), 0, ~0ull >> 2, &v);
                ref(x) = static_cast<N>(v);
            });
    }

    // Kích thước: "10GB"; ô trống nghĩa là 0 khi allow_empty.
    void size(const char* key, std::function<uint64_t&(T&)> ref, bool allow_empty, const char* hint = nullptr) {
        auto* t = new wxTextCtrl(win_, wxID_ANY, "");
        if (hint) t->SetHint(L(hint));
        t->SetMinSize(wxSize(120, -1));
        row(key, t, Browse::None, false);
        Check c = [allow_empty](const std::string& s) { return check_size(s, allow_empty); };
        add(key, t, [t] { return S(t->GetValue()); }, c, [t, ref](T& x) { t->ChangeValue(W(size_to_text(ref(x)))); },
            [t, ref](T& x) {
                uint64_t v = 0;
                check_size(S(t->GetValue()), true, &v);
                ref(x) = v;
            });
    }

    void mode(const char* key, std::function<uint32_t&(T&)> ref, bool is_dir) {
        auto* t = new wxTextCtrl(win_, wxID_ANY, "");
        t->SetMinSize(wxSize(120, -1));
        row(key, t, Browse::None, false);
        Check c = [is_dir](const std::string& s) { return check_octal_mode(s, is_dir); };
        add(key, t, [t] { return S(t->GetValue()); }, c, [t, ref](T& x) { t->ChangeValue(W(mode_to_text(ref(x)))); },
            [t, ref, is_dir](T& x) {
                uint32_t v = 0;
                check_octal_mode(S(t->GetValue()), is_dir, &v);
                ref(x) = v;
            });
    }

    void boolean(const char* key, std::function<bool&(T&)> ref) {
        auto* c = new wxCheckBox(win_, wxID_ANY, "");
        row(key, c, Browse::None, false);
        Item it;
        it.key = key;
        it.ctrl = c;
        it.validate = [] { return std::string(); };
        it.push = [c, ref](T& x) { c->SetValue(ref(x)); };
        it.assign = [c, ref](T& x) { ref(x) = c->GetValue(); };
        c->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent&) { if (on_edit_) on_edit_(); });
        items_.push_back(std::move(it));
    }

    void choice(const char* key, std::function<std::string&(T&)> ref, const std::vector<std::string>& opts) {
        auto* c = new wxChoice(win_, wxID_ANY);
        for (auto& o : opts) c->Append(W(o));
        row(key, c, Browse::None, false);
        Item it;
        it.key = key;
        it.ctrl = c;
        it.validate = [] { return std::string(); };
        it.push = [c, ref, opts](T& x) {
            int sel = 0;
            for (size_t i = 0; i < opts.size(); ++i)
                if (opts[i] == ref(x)) sel = static_cast<int>(i);
            c->SetSelection(sel);
        };
        it.assign = [c, ref, opts](T& x) {
            int s = c->GetSelection();
            if (s >= 0 && static_cast<size_t>(s) < opts.size()) ref(x) = opts[s];
        };
        c->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) { if (on_edit_) on_edit_(); });
        items_.push_back(std::move(it));
    }

    // Danh sách theo dòng; chk kiểm cả khối văn bản.
    void lines(const char* key, std::function<std::vector<std::string>&(T&)> ref, Check chk = {}, int rows = 3,
               const char* hint = nullptr) {
        auto* t = new wxTextCtrl(win_, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 20 * rows), wxTE_MULTILINE);
        if (hint) t->SetHint(L(hint));
        row(key, t, Browse::None);
        add(key, t, [t] { return S(t->GetValue()); }, chk,
            [t, ref](T& x) { t->ChangeValue(W(join_lines(ref(x)))); },
            [t, ref](T& x) { ref(x) = split_lines(S(t->GetValue())); });
    }

    // Ô tuỳ biến: bên ngoài cung cấp ctrl + hàm đẩy/kiểm/gán.
    void custom(const char* key, wxTextCtrl* t, Check chk, std::function<void(T&, wxTextCtrl*)> push,
                std::function<void(T&, const std::string&)> assign) {
        row(key, t, Browse::None);
        add(key, t, [t] { return S(t->GetValue()); }, chk, [t, push](T& x) { push(x, t); },
            [t, assign](T& x) { assign(x, S(t->GetValue())); });
    }

    // ---- vận hành
    void Push() {
        T* x = cur_();
        win_->Enable(x != nullptr);
        pushing_ = true;
        if (x)
            for (auto& it : items_) it.push(*x);
        else
            for (auto& it : items_)
                if (auto* tc = dynamic_cast<wxTextCtrl*>(it.ctrl)) tc->ChangeValue("");
        pushing_ = false;
        for (auto& it : items_) Mark(it);
    }
    // Kiểm mọi ô; không đổi struct nếu có lỗi. Trả về danh sách lỗi "nhãn: thông điệp".
    std::vector<std::string> Pull() {
        std::vector<std::string> errs;
        T* x = cur_();
        if (!x) return errs;
        for (auto& it : items_) {
            auto e = it.validate();
            if (!e.empty()) errs.push_back(S(L(it.key)) + ": " + e);
        }
        if (errs.empty())
            for (auto& it : items_) it.assign(*x);
        return errs;
    }
    void Revalidate() {
        for (auto& it : items_) Mark(it);
    }
    wxWindow* ctrl(const char* key) {
        for (auto& it : items_)
            if (std::string(it.key) == key) return it.ctrl;
        return nullptr;
    }
    bool AnyBad() const {
        for (auto& it : items_)
            if (!it.validate().empty()) return true;
        return false;
    }
    std::string FirstBad() const {
        for (auto& it : items_) {
            auto e = it.validate();
            if (!e.empty()) return S(L(it.key)) + ": " + e;
        }
        return "";
    }

private:
    struct Item {
        const char* key = "";
        wxWindow* ctrl = nullptr;
        std::function<std::string()> validate;
        std::function<void(T&)> push;
        std::function<void(T&)> assign;
    };

    void row(const char* key, wxWindow* ctrl, Browse br, bool expand = true) {
        grid_->Add(new wxStaticText(win_, wxID_ANY, L(key)), 0, wxALIGN_TOP | wxTOP, 4);
        grid_->Add(ctrl, expand ? 1 : 0, expand ? wxEXPAND : 0);
        if (br != Browse::None) {
            auto* b = new wxButton(win_, wxID_ANY, L("btn.browse"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
            grid_->Add(b, 0);
            b->Bind(wxEVT_BUTTON, [ctrl, br, this](wxCommandEvent&) {
                auto* t = dynamic_cast<wxTextCtrl*>(ctrl);
                if (!t) return;
                if (br == Browse::Dir) {
                    wxDirDialog d(win_, L("btn.browse"), t->GetValue());
                    if (d.ShowModal() == wxID_OK) t->SetValue(d.GetPath());
                } else {
                    wxFileDialog d(win_, L("btn.browse"), "", "", "*.*",
                                   br == Browse::FileSave ? wxFD_SAVE : (wxFD_OPEN | wxFD_FILE_MUST_EXIST));
                    if (d.ShowModal() == wxID_OK) t->SetValue(d.GetPath());
                }
            });
        } else {
            grid_->AddSpacer(1);
        }
    }

    void add(const char* key, wxTextCtrl* t, std::function<std::string()> get, Check chk, std::function<void(T&)> push,
             std::function<void(T&)> assign) {
        Item it;
        it.key = key;
        it.ctrl = t;
        it.validate = [get, chk]() { return chk ? chk(get()) : std::string(); };
        it.push = std::move(push);
        it.assign = std::move(assign);
        items_.push_back(std::move(it));
        size_t idx = items_.size() - 1;
        t->Bind(wxEVT_TEXT, [this, idx](wxCommandEvent& e) {
            e.Skip();
            if (pushing_ || idx >= items_.size()) return;
            Mark(items_[idx]);
            if (on_edit_) on_edit_();
        });
    }

    void Mark(Item& it) {
        auto* t = dynamic_cast<wxTextCtrl*>(it.ctrl);
        if (!t) return;
        std::string e = it.validate();
        if (e.empty()) {
            t->SetBackgroundColour(wxNullColour);
            t->SetForegroundColour(wxNullColour);
            t->UnsetToolTip();
        } else {
            t->SetBackgroundColour(wxColour(0xFF, 0xDD, 0xDD));
            t->SetForegroundColour(wxColour(0, 0, 0));
            t->SetToolTip(W(e));
        }
        t->Refresh();
    }

    Cur cur_;
    std::function<void()> on_edit_;
    wxScrolledWindow* win_;
    wxFlexGridSizer* grid_;
    std::vector<Item> items_;
    bool pushing_ = false;
};

}  // namespace mysync::gui
