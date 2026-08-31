//! Transport : tube nomme vers le processus d'interface.
//!
//! # Choix de conception
//!
//! C'est l'**interface** qui cree le tube, et le helper qui s'y connecte.
//! L'inverse serait plus naturel, mais Windows l'interdit en pratique : un
//! tube cree par un processus eleve herite d'un niveau d'integrite eleve, et
//! un processus d'integrite moyenne — l'interface — ne peut pas y ecrire. En
//! creant le tube du cote non privilegie, l'ecriture se fait du haut vers le
//! bas, ce qui est toujours autorise.
//!
//! Le nom du tube est tire au hasard a chaque lancement et valide caractere
//! par caractere par [`crate::is_valid_pipe_name`] avant d'etre utilise.
//!
//! Aucune API systeme brute n'est necessaire : sous Windows, un tube nomme
//! s'ouvre et se lit comme un fichier ordinaire. Ce module ne contient donc
//! aucun code `unsafe`.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};

/// Taille maximale d'une ligne de protocole.
///
/// Un instantane firmware complet reste tres en deca ; au-dela, il s'agit
/// forcement de donnees aberrantes, qu'on refuse plutot que d'allouer sans
/// limite.
const MAX_LINE: usize = 4 * 1024 * 1024;

/// Connexion ouverte vers l'interface.
#[derive(Debug)]
pub struct Connection {
    reader: BufReader<std::fs::File>,
    writer: std::fs::File,
}

impl Connection {
    /// Se connecte au tube nomme cree par l'interface.
    pub fn connect(pipe_name: &str) -> io::Result<Connection> {
        let path = format!(r"\\.\pipe\{pipe_name}");

        let handle = OpenOptions::new().read(true).write(true).open(&path)?;
        let writer = handle.try_clone()?;

        Ok(Connection {
            reader: BufReader::new(handle),
            writer,
        })
    }

    /// Lit une ligne. `None` signale que l'interface a ferme la connexion,
    /// ce qui est la facon normale de terminer le helper.
    pub fn read_line(&mut self) -> io::Result<Option<String>> {
        let mut line = String::new();
        let mut total = 0usize;

        loop {
            let mut chunk = String::new();
            let n = self.reader.read_line(&mut chunk)?;
            if n == 0 {
                return Ok(if line.is_empty() { None } else { Some(line) });
            }

            total += n;
            if total > MAX_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ligne de protocole demesuree",
                ));
            }

            line.push_str(&chunk);
            if line.ends_with('\n') {
                return Ok(Some(line.trim_end().to_string()));
            }
        }
    }

    /// Envoie une ligne, terminee et vidée immediatement.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connecting_to_a_nonexistent_pipe_fails_without_panicking() {
        let err = Connection::connect("bootsel-nexistepas0123456789").unwrap_err();
        // Le helper doit sortir proprement, pas paniquer.
        assert!(matches!(
            err.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn the_path_is_built_in_the_pipe_namespace() {
        // Garde-fou : le nom valide ne peut pas sortir de \\.\pipe\.
        let name = "bootsel-0123456789abcdef";
        assert!(crate::is_valid_pipe_name(name));
        let path = format!(r"\\.\pipe\{name}");
        assert!(path.starts_with(r"\\.\pipe\"));
        assert!(!path.contains(".."));
    }
}
