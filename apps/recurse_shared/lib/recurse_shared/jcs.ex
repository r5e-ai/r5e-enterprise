defmodule Recurse.Shared.Jcs do
  @moduledoc """
  RFC 8785 JSON Canonicalization Scheme (JCS) encoder.

  JCS produces a deterministic, byte-stable JSON encoding. Used across
  Recurse wherever a JSON document must be cryptographically hashed
  (FR-026 principal canonicalization, FR-021 in-toto predicate payload,
  FR-039 Cedar `policy_canonical_hash`).

  Phase-1 implementation scope:

    * Object keys sorted lexicographically on UTF-16 code units
      (approximated via `:unicode.characters_to_binary/2` UTF-16
      ordering; ASCII keys are byte-identical).
    * Arrays preserve insertion order (no sort).
    * Strings: UTF-8 bytes, escaped per RFC 8259 §7 with the RFC 8785
      "shortest-escape" rule (control chars, `"`, `\\`, and only those
      multi-byte forms that require `\\uXXXX` surrogate pairs).
    * Numbers: only integers and safe floats. RFC 8785 §3.2.2.3 ECMA-262
      7.1.12.1 number formatting is approximated for integers (decimal,
      no leading zeros, negative-zero collapsed to zero) and rejected
      for non-integer floats that can't round-trip (we prefer crashing
      honestly to silently rounding). In-toto/Principal/Cedar payloads
      never carry floats in Phase 1.
    * Booleans, `nil` → `true` / `false` / `null` (byte-identical).

  ## Constraints

  The Phase-1 JCS implementation does NOT cover the full RFC 8785
  surface (no scientific-notation floats, no non-UTF-8 strings). This
  is sufficient for the Principal / in-toto-predicate / Cedar-AST use
  cases we have; extending it is tracked under Feature 002+ if needed.

  Property-tested for byte-stability under key-order perturbation in
  `test/principal_property_test.exs` and
  `test/attestation/in_toto_property_test.exs`.
  """

  @type json_value ::
          nil
          | boolean()
          | integer()
          | String.t()
          | [json_value()]
          | %{optional(String.t()) => json_value()}

  @doc """
  Encode a JSON-compatible Elixir term into RFC 8785 canonical bytes.
  """
  @spec encode(json_value()) :: binary()
  def encode(value), do: IO.iodata_to_binary(encode_value(value))

  # --- internals ---

  defp encode_value(nil), do: "null"
  defp encode_value(true), do: "true"
  defp encode_value(false), do: "false"

  defp encode_value(int) when is_integer(int) do
    Integer.to_string(int)
  end

  defp encode_value(float) when is_float(float) do
    # Only whole-valued floats can round-trip safely under the reduced
    # JCS number rules we support. Non-integer floats are rejected.
    if float == Float.floor(float) and abs(float) < 1.0e16 do
      float |> trunc() |> Integer.to_string()
    else
      raise ArgumentError, "JCS Phase-1 does not encode non-integer floats: #{inspect(float)}"
    end
  end

  defp encode_value(bin) when is_binary(bin), do: encode_string(bin)

  defp encode_value(list) when is_list(list) do
    items = Enum.map(list, &encode_value/1)
    ["[", Enum.intersperse(items, ","), "]"]
  end

  defp encode_value(%_{} = struct),
    do: raise(ArgumentError, "JCS expects plain maps, got struct #{inspect(struct.__struct__)}")

  defp encode_value(map) when is_map(map) do
    pairs =
      map
      |> Enum.map(fn {k, v} -> {key_to_string(k), v} end)
      |> Enum.sort_by(fn {k, _v} -> utf16_key(k) end)
      |> Enum.map(fn {k, v} -> [encode_string(k), ":", encode_value(v)] end)

    ["{", Enum.intersperse(pairs, ","), "}"]
  end

  defp key_to_string(k) when is_binary(k), do: k
  defp key_to_string(k) when is_atom(k), do: Atom.to_string(k)

  defp utf16_key(k) do
    # JCS (RFC 8785 §3.2.3) sorts object keys by UTF-16 code-unit value.
    # `:unicode.characters_to_binary/3` → UTF-16 gives us that ordering
    # when compared as a binary.
    :unicode.characters_to_binary(k, :utf8, {:utf16, :big})
  end

  defp encode_string(bin) do
    [?", escape(bin, <<>>), ?"]
  end

  # Escape per RFC 8259 §7 with RFC 8785 §3.2.2.2 short-form rules:
  # - `"`  → `\"`
  # - `\`  → `\\`
  # - `\b` → `\b` (0x08); `\f` → `\f` (0x0C); `\n` → `\n`; `\r` → `\r`; `\t` → `\t`
  # - other controls (0x00-0x1F) → `\uXXXX`
  # - all other UTF-8 bytes pass through unchanged
  defp escape(<<>>, acc), do: acc
  defp escape(<<?", rest::binary>>, acc), do: escape(rest, acc <> "\\\"")
  defp escape(<<?\\, rest::binary>>, acc), do: escape(rest, acc <> "\\\\")
  defp escape(<<0x08, rest::binary>>, acc), do: escape(rest, acc <> "\\b")
  defp escape(<<0x09, rest::binary>>, acc), do: escape(rest, acc <> "\\t")
  defp escape(<<0x0A, rest::binary>>, acc), do: escape(rest, acc <> "\\n")
  defp escape(<<0x0C, rest::binary>>, acc), do: escape(rest, acc <> "\\f")
  defp escape(<<0x0D, rest::binary>>, acc), do: escape(rest, acc <> "\\r")

  defp escape(<<byte, rest::binary>>, acc) when byte < 0x20 do
    hex = byte |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0")
    escape(rest, acc <> "\\u" <> hex)
  end

  defp escape(<<byte, rest::binary>>, acc) do
    escape(rest, acc <> <<byte>>)
  end
end
