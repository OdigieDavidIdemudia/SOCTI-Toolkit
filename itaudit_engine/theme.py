GT_THEME = {
  "app_name": "GT DataSplit",
  "theme_toggle": {
    "enabled": True,
    "default_mode": "light",
    "toggle_component": {
      "type": "switch",
      "size": "medium",
      "thumb_radius": 8,
      "transition_duration_ms": 180
    }
  },

  "layout": {
    "grid": 4,
    "padding": 16,
    "section_spacing": 24,
    "rounded_corners": 4
  },

  "themes": {
    "light": {
      "name": "GTCO Light",
      "colors": {
        "primary": "#FF6600",
        "primary_hover": "#E65A00",
        "background": "#FAFAFA",
        "surface": "#FFFFFF",
        "border": "#E6E6E6",
        "text_primary": "#1E1E1E",
        "text_secondary": "#8C8C8C",
        "table_header_bg": "#F5F5F5",
        "table_row_hover": "#FFF5EF",
        "input_bg": "#FFFFFF",
        "input_border": "#D9D9D9",
        "input_focus_border": "#FF6600"
      },

      "typography": {
        "font_family": "Inter, Segoe UI, sans-serif", # CustomTkinter uses tuple ("Family", size)
        "h1": 24,
        "h2": 18,
        "body": 14,
        "label": 12,
        "weight_regular": "normal",
        "weight_medium": "normal", # CTk doesn't support medium weight explicitly usually
        "weight_semibold": "bold"
      },

      "components": {
        "button_primary": {
          "bg": "#FF6600",
          "text": "#FFFFFF",
          "height": 40,
          "radius": 4
        },
        "button_secondary": {
          "bg": "#FFFFFF",
          "text": "#1E1E1E",
          "border": "#E6E6E6",
          "height": 40,
          "radius": 4
        },
        "input": {
          "height": 36,
          "bg": "#FFFFFF",
          "border": "#D9D9D9",
          "radius": 4,
          "text_color": "#1E1E1E",
          "placeholder": "#A8A8A8"
        }
      }
    },

    "dark": {
      "name": "GTCO Dark",
      "colors": {
        "primary": "#FF6600",
        "primary_hover": "#CC5200",
        "background": "#121212",
        "surface": "#1A1A1A",
        "border": "#333333",
        "text_primary": "#FFFFFF",
        "text_secondary": "#C4C4C4",
        "table_header_bg": "#1F1F1F",
        "table_row_hover": "#332214",
        "input_bg": "#1A1A1A",
        "input_border": "#333333",
        "input_focus_border": "#FF6600"
      },

      "typography": {
        "font_family": "Inter, Segoe UI, sans-serif",
        "h1": 24,
        "h2": 18,
        "body": 14,
        "label": 12,
        "weight_regular": "normal",
        "weight_medium": "normal",
        "weight_semibold": "bold"
      },

      "components": {
        "button_primary": {
          "bg": "#FF6600",
          "text": "#FFFFFF",
          "height": 40,
          "radius": 4
        },
        "button_secondary": {
          "bg": "#1A1A1A",
          "text": "#FFFFFF",
          "border": "#333333",
          "height": 40,
          "radius": 4
        },
        "input": {
          "height": 36,
          "bg": "#1A1A1A",
          "border": "#333333",
          "radius": 4,
          "text_color": "#FFFFFF",
          "placeholder": "#888888"
        }
      }
    }
  }
}
