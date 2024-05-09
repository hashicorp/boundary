// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package help

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/website/content"
	"github.com/hashicorp/go-hclog"
	"github.com/pgvector/pgvector-go"
	"github.com/philippgille/chromem-go"
)

type Embedder interface {
	CreateEmbedding(ctx context.Context, texts []string) ([][]float32, error)
}

const (
	useInMemoryDB      = false
	defaultNumHintDocs = 5
)

type Searcher struct {
	logger      hclog.Logger
	reader      db.Reader
	writer      db.Writer
	embedder    Embedder
	cdb         *chromem.Collection
	numHintDocs int
}

func NewSearcher(ctx context.Context, logger hclog.Logger, w db.Writer, r db.Reader, embedder Embedder, numHintDocs int) (*Searcher, error) {
	cdb, err := chromem.NewDB().CreateCollection("boundary", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create in-memory vector DB: %w", err)
	}
	if numHintDocs < 0 {
		return nil, fmt.Errorf("numHintDocs must be non-negative")
	}
	if numHintDocs == 0 {
		numHintDocs = defaultNumHintDocs
	}
	return &Searcher{
		logger:      logger,
		reader:      r,
		writer:      w,
		embedder:    embedder,
		cdb:         cdb,
		numHintDocs: numHintDocs,
	}, nil
}

func (s *Searcher) CreateEmbeddings(ctx context.Context) error {
	var paths []string
	var texts []string
	s.logger.Info("Collecting docs")
	err := fs.WalkDir(content.DocsFS, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to walk dir: %w", err)
		}
		content, err := fs.ReadFile(content.DocsFS, path)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %w", path, err)
		}
		paths = append(paths, path)
		texts = append(texts, string(content))
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to collect docs")
	}
	t := time.Now()
	embeddings, err := s.embedder.CreateEmbedding(ctx, texts)
	if err != nil {
		return fmt.Errorf("failed to get embeddings: %w", err)
	}
	s.logger.Info("Embedding creation complete", "numDocs", len(texts), "took", time.Since(t))
	if len(embeddings) != len(paths) {
		return fmt.Errorf("expected %v embeddings; got %v", len(paths), len(embeddings))
	}
	if useInMemoryDB {
		if err := s.cdb.Add(ctx, paths, embeddings, nil, texts); err != nil {
			return fmt.Errorf("failed to add embeddings to in-memory DB: %w", err)
		}
	} else {
		// Truncate any existing docs in the DB, since docs may have been updated
		_, err = s.writer.Exec(ctx, "truncate doc", nil)
		if err != nil {
			return fmt.Errorf("failed to truncate existing embeddings")
		}
		for i, path := range paths {
			_, err := s.writer.Exec(
				ctx,
				"insert into doc (path, content, embedding) values ($1, $2, $3)",
				[]any{
					path,
					texts[i],
					pgvector.NewVector(embeddings[i]),
				},
			)
			if err != nil {
				return fmt.Errorf("failed to insert doc %q: %w", path, err)
			}
		}
	}

	return nil
}

func (s *Searcher) FindTopDocsForQuery(ctx context.Context, query string) ([]string, error) {
	embeddings, err := s.embedder.CreateEmbedding(ctx, []string{query})
	if err != nil {
		return nil, fmt.Errorf("failed to get embedding for query: %w", err)
	}
	if len(embeddings) != 1 {
		return nil, fmt.Errorf("expected 1 embedding; got %v", len(embeddings))
	}

	var paths []string
	var texts []string
	if useInMemoryDB {
		results, err := s.cdb.QueryEmbedding(ctx, embeddings[0], s.numHintDocs, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to query embeddings from vector DB: %w", err)
		}
		for _, result := range results {
			paths = append(paths, result.ID)
			texts = append(texts, result.Content)
		}
	} else {
		rows, err := s.reader.Query(ctx, fmt.Sprintf("select path, content from doc order by embedding <-> $1 limit %d", s.numHintDocs), []any{pgvector.NewVector(embeddings[0])})
		if err != nil {
			return nil, fmt.Errorf("failed to get top matches: %w", err)
		}
		for rows.Next() {
			var path string
			var text string
			err := rows.Scan(&path, &text)
			if err != nil {
				return nil, fmt.Errorf("failed to scan row: %w", err)
			}
			paths = append(paths, path)
			texts = append(texts, text)
		}
	}

	s.logger.Info("Top matches for query", "query", query, "paths", paths)
	return texts, nil
}
