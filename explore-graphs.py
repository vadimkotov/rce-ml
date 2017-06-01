import sys
import os

from core import disassembler
from core import database
from core import utils


import networkx as nx
import subprocess

import random

SAMPLE_SIZE = 10

OUT_DIR = 'graph_shapes'

def write_file(path, data):
    fd = open(path, 'wb')
    fd.write(data)
    fd.close()


def save_shape(g, name):
    dot_ = ''

    if not g.edges():
        dot_ += 'n1'
    else:
        for e in g.edges():
            dot_ += 'n%d -> n%d\n' % e


    dot_ = 'digraph {\n%s}' % dot_

    dot_path = os.path.join(OUT_DIR, name + '.dot')
    pdf_path = os.path.join(OUT_DIR, name + '.pdf')

    write_file(dot_path, dot_)

    subprocess.call(['dot', '-Tpdf', '-o%s' % pdf_path, "-Nlabel=", dot_path])

def main():
    if len(sys.argv) != 2:
        print 'Usage: %s <sqlite>' % sys.argv[0]
        sys.exit()


    fd = open('log.txt', 'wb')

    db = database.Database(sys.argv[1])

    sample = db.get_random_functions(SAMPLE_SIZE)


    graphs = []
    labels = []
    blobs = []
    files = []

    for func in sample:
        file_ = db.get_file_by_id(func['file_id'])
        bytes_ = utils.decompress(func['bytes'])

        d = disassembler.Disassembler(bytes_, func['virtual_address'])
        d.disassemble()

        try:
            d.build_cfg()
        except RuntimeError as e:
            sys.stderr.write('%s %s %s %s\n' % (str(e), file_['path'], func['name'], hex(func['virtual_address'])))
            continue

        graphs.append(d.graph)

        label = '%d.%d.%s.%s.%s' % (func['rowid'], func['file_id'], os.path.basename(file_['path']), func['name'], hex(func['virtual_address']))
        labels.append(label)
        files.append(os.path.basename(file_['path']))


        # blobs.append(bytes_)

    # groups = {k:[] for k in xrange(len(graphs))}
    group_cnt = 0
    groups = {}

    closed_list = []

    for i in xrange(len(graphs)):
        fd.write('Checking %d\n' % i)

        if i in closed_list:
            fd.write('%d is in closed list, skipping\n' % i)
            continue

        groups[i] = {'shape': graphs[i], 'cnt': 1, 'ids': [i], 'files': [files[i]]}
        closed_list.append(i)

        for j in xrange(i+1, len(graphs)):
            fd.write('Compating %d with %d\n' % (i, j))

            if j in closed_list:
                fd.write('%d is in closed list, skipping\n' % j)
                continue

            if nx.is_isomorphic(graphs[i], graphs[j]):
                fd.write('%d and %d are isomorphic\n' % (i, j))

                groups[i]['cnt'] += 1
                groups[i]['ids'].append(j)
                groups[i]['files'].append(files[j])
                closed_list.append(j)


    cnt = 1

    for id, obj in sorted(groups.iteritems(), key=lambda x: len(set(x[1]['files'])), reverse=True):

        g = obj['shape']
        n_files = len(set(obj['files']))

        # if obj['cnt'] > 1:
        if n_files > 2:
            name = '%.3d' % cnt
            save_shape(g, name)

            ids = obj['ids']

            fd.write('IDS OF SHAPE %d\n' % cnt)
            for id in ids:
                fd.write('\t%d\n' % id)

            if len(ids) > 10:
                ids = random.sample(ids, 10)

            for id in ids:
                label = labels[id]
                if len(label) > 80:
                    label = label[:80]
                path = os.path.join('blobs', '%.3d-%s' % (cnt, label))
                

        cc = len(g.edges()) - len(g.nodes()) + 2
        print '%d,%d,%d,%d' % (cnt, obj['cnt'], n_files, cc)
        cnt += 1

    fd.close()


if __name__ == '__main__':
    main()
