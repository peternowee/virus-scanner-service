import { NamedNode, triple } from 'rdflib';
import bodyParser from 'body-parser';
import { LOG_INCOMING_DELTA, LOG_INCOMING_SCAN_REQUESTS } from './config';
import {
  app,
  errorHandler,
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
  uuid,
} from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { Delta } from './lib/delta';
import { existsSync } from 'node:fs';
import NodeClam from 'clamscan';

const STIX_MALWARE_RESULT_OV = ['benign', 'suspicious', 'malicious', 'unknown'];

app.use(bodyParser.json({ limit: '50mb' }));

app.get('/', function (req, res) {
  res.send('Hello from virus-scanner-service');
});

app.post(
  '/delta',
  async function (req, res) {
    try {
      const body = req.body;
      if (LOG_INCOMING_DELTA) {
        console.log(`Receiving delta : ${JSON.stringify(body)}`);
      }

      const delta = new Delta(req.body);

      if (!delta.inserts.length) {
        console.log(
          'Delta does not contain any insertions. Nothing should happen.',
        );
        return res.status(204).send();
      }

      const filesInDelta = delta
        .getInsertsFor(
          triple(
            undefined,
            new NamedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
            new NamedNode(
              'http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#FileDataObject',
            ),
          ),
        )
        .map((insert) => insert.subject.value);

      const logicalFilesInDelta = filesInDelta.filter(
        (fileIRI) => !fileIRI.startsWith('share://'),
      );

      if (!logicalFilesInDelta.length) {
        console.log(
          'No FileDataObject inserts for logical files. Nothing should happen.',
        );
        return res.status(204).send();
      }

      res.status(202).send();

      const filesToScan = [...new Set(logicalFilesInDelta)]; //make them unique

      console.log('File IRIs to be scanned: ' + JSON.stringify(filesToScan));

      const fileResults = [];

      for (const file of filesToScan) {
        const scanFileResult = await scanFile(file);

        const storeResult = await storeMalwareAnalysis(
          file,
          scanFileResult.stixMalwareAnalysis,
        );

        fileResults.push({
          file,
          ...scanFileResult,
          ...storeResult,
        });
      }

      console.log('Finished scanning files.');
      console.log('\nDetailed results per file:');
      console.dir(fileResults, { depth: null });

      console.log('\nFiles per STIX Malware Analysis result:');
      const resultValues = [
        ...new Set([
          ...STIX_MALWARE_RESULT_OV,
          ...fileResults
            .map((fileResult) => fileResult.stixMalwareAnalysis.result)
            .sort(),
        ]),
      ];
      resultValues.map((resultValue) => {
        console.log('- ' + resultValue + ' :');
        console.log(
          fileResults
            .filter(
              (fileResult) =>
                fileResult.stixMalwareAnalysis.result === resultValue,
            )
            .map((fileResult) => fileResult.file),
        );
      });

      // TODO: Let storeMalwareAnalysis() run a SELECT query after the insert
      //       to check in which (if any) graphs the resource was inserted?
      //       Would be more reliable and easier to parse.
      const filesNoDatabaseUpdate = fileResults.filter(
        (fileResult) =>
          !(
            fileResult.databaseResponse?.results?.bindings[0]?.['callret-0']
              ?.value &&
            fileResult.databaseResponse?.results?.bindings[0]?.[
              'callret-0'
            ]?.value.match(' -- done')
          ),
      );
      if (filesNoDatabaseUpdate.length) {
        console.log(
          '\nFiles for which the database response indicates that the ' +
            'malware analysis resource object was not added to any graph:',
        );
        console.dir(filesNoDatabaseUpdate, { depth: null });
      }
    } catch (e) {
      console.log(e);
      res.status(500).send('Uncaught error in /delta: ' + e);
      // TODO: Re-throw error? Because not sure if the response 500
      //       will be received (e.g. /delta already sent 202 or /post
      //       connection timeout during long scan). If the result was
      //       not "benign", but not stored because of an error, an
      //       earlier "benign" result for the same file will remain the
      //       latest result. Perhaps such errors should require more
      //       attention.
      //       OTOH: - Re-throwing lets the entire service crash.
      //       - Perhaps it is the user's responsibility anyway to
      //       check that the last malware-analyse is recent enough.
      //       - Already a note about this in README.
      //       Could be somewhat mitigated by storing a malware analysis
      //       with only analysis-started before the scan, and update it
      //       after the scan.
    }
  },
);

/**
 * Scans a single file and stores the result.
 *
 * @param {Object} body Request body should be in JSON-format with
 *                      `file` containing a logical file IRI as a single String.
 *                      E.g. { "file": "http://mu.semte.ch/services/file-service/files/6543bc046ea4f3000e00000c" }
 * @return [201] if file was found in database, a malware analysis ran and the
 *               results were sent to the database. The response body contains
 *               the malware analysis results and the database response.
 *               - If the scan failed, the result will be "unknown".
 *               - If databaseResponse is null the result was not inserted in
 *                 any graph, most likely because file IRI was not in any graph.
 * @return [400] if request malformed.
 * @return [422] if no related physical file is found in database.
 */
app.post(
  '/scan',
  async function (req, res) {
    try {
      const body = req.body;
      if (LOG_INCOMING_SCAN_REQUESTS) {
        console.log(`Receiving scan request : ${JSON.stringify(body)}`);
      }

      const logicalFileIRI = body.file;
      if (
        !(
          typeof logicalFileIRI === 'string' || logicalFileIRI instanceof String
        ) ||
        !logicalFileIRI.length
      ) {
        return res.status(400).send('`file` not a non-empty String');
      }

      if (logicalFileIRI.startsWith('share://')) {
        // TODO: Be flexible and lookup the logical file IRI? Can we assume
        //       that, even if the physical file IRI exists in multiple graphs,
        //       they will all be related to the same logical file IRI?
        return res
          .status(422)
          .send('`file` is a physical file IRI, should be a logical file IRI');
      }

      // TODO: Check for existence of `<logicalFileIRI> a nfo:FileDataObject`?

      const scanFileResult = await scanFile(logicalFileIRI);

      const storeResult = await storeMalwareAnalysis(
        logicalFileIRI,
        scanFileResult.stixMalwareAnalysis,
      );

      console.dir(
        {
          file: logicalFileIRI,
          ...scanFileResult,
          ...storeResult,
        },
        { depth: null },
      );

      res.status(201).send(storeResult.resourceObject);
    } catch (e) {
      console.log(e);
      res.status(500).send('Uncaught error in /scan: ' + e);
      // TODO: Same question as for /delta: Re-throw error?
    }
  },
);

app.use(errorHandler);

/**
 * Scans a file for viruses.
 *
 * @async
 * @function
 * @param {String} fileIRI - IRI file to scan. This can be a logical/virtual
 *                           file IRI or a physical/stored file IRI.
 * @returns {Object} Properties:
 *          .stixMalwareAnalysis - The malware analysis details. Remarks:
 *                                 - result: If "unknown", see .error.
 *                                 - sampleRef: Not set, see .lookups.
 *          .error - Error object (if any).
 *          .lookups - Results of lookups from the requested file IRI to
 *                     the physical file path.
 */
async function scanFile(fileIRI) {
  const ret = {
    stixMalwareAnalysis: {
      analysisStarted: new Date(),
      analysisEnded: undefined,
      result: 'unknown',
      resultName: undefined,
    },
    error: undefined,
    lookups: undefined,
  };
  let physicalFileIRI;
  let file;

  try {
    physicalFileIRI = fileIRI.startsWith('share://')
      ? fileIRI
      : await getPhysicalFileIRI(fileIRI);
    if (physicalFileIRI === null) {
      throw new Error('No physical file IRI found for: ' + fileIRI);
    }

    file = filePathFromIRI(physicalFileIRI);

    if (!existsSync(file)) {
      throw new Error('File not found on disk: ' + JSON.stringify(file));
    }
    const clamscanResult = await clamscanFile(file);
    const fileHasVirus = clamscanResult.isInfected;
    switch (fileHasVirus) {
      case false:
        ret.stixMalwareAnalysis.result = 'benign';
        break;
      case true:
        ret.stixMalwareAnalysis.result = 'malicious';
        ret.stixMalwareAnalysis.resultName = JSON.stringify(
          clamscanResult.viruses,
        );
        break;
      case null:
        throw new Error('clamscan JS returned null: Unable to scan');
        break; // eslint-disable-line no-unreachable
      default:
        throw new Error('Unexpected return value from clamscan JS');
    }
  } catch (e) {
    ret.error = e;
  }
  ret.stixMalwareAnalysis.analysisEnded = new Date();
  ret.lookups = {
    requestedFileIRI: fileIRI,
    physicalFileIRI,
    physicalFilePath: file,
  };
  console.log(ret);
  return ret;
}

/**
 * Calls the clamscan JS library to scan a file for viruses.
 *
 * @async
 * @function
 * @param {String} path - Path of file to scan.
 * @returns {Object} As per clamscan 2.1.2:
 * - `file` (string) The original `filePath` passed into the `isInfected`
 *                   method.
 * - `isInfected` (boolean) **True**: File is infected;
 *                          **False**: File is clean.
 *                          **NULL**: Unable to scan.
 * - `viruses` (array) An array of any viruses found in the scanned file.
 */
async function clamscanFile(path) {
  console.log('Running virus scan on file: ' + JSON.stringify(path));
  const scanner = await new NodeClam().init({
    clamscan: {
      // Do not use clamscan binary because it loads database on every run.
      active: false,
    },
    clamdscan: {
      socket: '/var/run/clamav/clamd.ctl', // Unix domain socket
      host: false, // Do not connect via TCP interface
      port: false, // Do not connect via TCP interface
      localFallback: false, // Do not use local preferred binary to scan if socket/tcp fails
      active: true,
    },
    preference: 'clamdscan',
  });
  const result = await scanner.isInfected(path);
  console.log(result);
  return result;
  // For now, error handling will be the responsibility of the function caller.
}

/**
 * Gets the physical file IRI associated to a virtual/logical file IRI
 */
async function getPhysicalFileIRI(logicalFileIRI) {
  const result = await query(`
    PREFIX nie: <http://www.semanticdesktop.org/ontologies/2007/01/19/nie#>
    SELECT ?physicalFile
    WHERE {
      GRAPH ?g {
        ?physicalFile nie:dataSource ${sparqlEscapeUri(logicalFileIRI)} .
      }
    }
  `);
  if (result.results.bindings.length)
    // `[0]` is based on the assumption that, even if there are triples
    // for the logical file IRI in multiple graphs, they will all be
    // related to the same physical file IRI, so the array will always
    // only contain 1 physical file IRI.
    return result.results.bindings[0]['physicalFile'].value;
  return null;
}

/**
 * Converts a physical file IRI to a file path
 *
 * The URI of the stored file uses the share:// protocol and
 * reflects the location where the file resides as a relative
 * path to the share folder. E.g. share://uploads/my-file.pdf
 * means the file is stored at /share/uploads/my-file.pdf.
 * -- https://github.com/mu-semtech/file-service/blob/v3.3.0/README.md#description
 */
function filePathFromIRI(physicalFileIRI) {
  return physicalFileIRI.replace(/^share:\/\//, '/share/');
}

/**
 * Stores the result of a malware-scan in the database.
 *
 * A stix:MalwareAnalysis resource is stored in all graphs containing the
 * supplied file IRI.
 *
 * Notes:
 * - This function does not lookup and flag related file IRIs. If both the
 *   logical/virtual file IRI and physical/stored file IRI need to be flagged,
 *   call this function again for each IRI.
 * - If fileIRI does not exist in any graph in the database, the returned
 *   resource object will not have been inserted anywhere in the database.
 *
 * @param {String} fileIRI - IRI of the file to be flagged.
 * @param {Object} stixMalwareAnalysis - The malware analysis details.
 *        Properties: .analysisStarted: Timestamp of start of analysis.
 *                    .analysisEnded  : Timestamp of end of analysis.
 *                    .result : Usually one of the values from
 *                        STIX 2.1 Malware Result Vocabulary malware-result-ov:
 *                        "malicious", "suspicious", "benign" or "unknown".
 *                        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_dtrq0daddkwa
 *                    .resultName : JSON string of array of viruses found.
 * @return {Object} Properties:
 *    .resourceObject: JavaScript object representation of the malware
 *                     analysis resource object.
 *    .databaseResponse: null if not inserted in any graph. Otherwise
 *        .results.bindings[0].['callret-0'].value {String} Textual database
 *            response mentioning the graphs in which the malware analysis
 *            resource object was inserted (may still be 0, check response).
 */
async function storeMalwareAnalysis(fileIRI, stixMalwareAnalysis) {
  const ret = {
    resourceObject: undefined,
    databaseResponse: undefined,
  };

  const malwareAnalysisId = uuid();
  // TODO: Not http://data.gift/id/virus-scanner/analysis/1 ?
  //       or: http://data.gift/services/id/virus-scanner/analysis/1 ?
  const malwareAnalysisIri =
    'http://data.gift/virus-scanner/analysis/id/'.concat(malwareAnalysisId);

  let databaseResponse;
  try {
    databaseResponse = await update(`
      PREFIX stix: <http://docs.oasis-open.org/cti/ns/stix#>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX nfo: <http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#>
      INSERT {
        GRAPH ?g {
          ${sparqlEscapeUri(malwareAnalysisIri)}
            a stix:MalwareAnalysis;
            mu:uuid ${sparqlEscapeString(malwareAnalysisId)};
            stix:analysis_started ${sparqlEscapeDateTime(
              stixMalwareAnalysis.analysisStarted,
            )};
            stix:analysis_ended ${sparqlEscapeDateTime(
              stixMalwareAnalysis.analysisEnded,
            )};
            stix:result ${sparqlEscapeString(stixMalwareAnalysis.result)};
            stix:sample_ref ${sparqlEscapeUri(fileIRI)} .
        }
      }
      WHERE {
        GRAPH ?graph {
          ${sparqlEscapeUri(fileIRI)} a nfo:FileDataObject .
        }
        BIND(?graph AS ?g)
      }
    `);
  } catch (e) {
    console.log(
      `Failed to store malware analysis of <${fileIRI}> in triplestore: \n ${e}`,
    );
    throw e;
  }

  ret.resourceObject = {
    data: {
      type: 'malware-analyses',
      id: malwareAnalysisId,
      attributes: {
        // TODO: Ok to include uri? Not a property in database, but
        //       mu-cl-resource include-uri also adds it as an attribute.
        uri: malwareAnalysisIri,
        'analysis-started': stixMalwareAnalysis.analysisStarted,
        'analysis-ended': stixMalwareAnalysis.analysisEnded,
        result: stixMalwareAnalysis.result,
        'sample-ref': fileIRI,
      },
    },
    // TODO: links.self
  };
  ret.databaseResponse = databaseResponse;
  console.log(ret);
  return ret;
}
